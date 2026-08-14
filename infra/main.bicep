targetScope = 'resourceGroup'

@minLength(1)
@maxLength(64)
@description('Name of the environment which is used to generate a short unique hash for resources.')
param environmentName string

@minLength(1)
@description('Primary location for all resources')
param location string = resourceGroup().location

param seedAddr string = ''

@description('Administrator login of the PostgreSQL flexible server holding the node ledger.')
param postgresAdminUser string = 'revika'

@secure()
@minLength(8)
@description('Administrator password of the PostgreSQL flexible server holding the node ledger.')
param postgresAdminPassword string

var resourceToken = toLower(uniqueString(subscription().id, environmentName, location))
var tags = { 'azd-env-name': environmentName }

var postgresServerName = 'psql-${resourceToken}'
var postgresDatabaseName = 'revika'
var postgresFqdn = '${postgresServerName}.postgres.database.azure.com'

// sslmode=require: Azure PostgreSQL refuses unencrypted connections.
var ledgerDsn = 'postgres://${postgresAdminUser}:${uriComponent(postgresAdminPassword)}@${postgresFqdn}:5432/${postgresDatabaseName}?sslmode=require'

// Node command line. The node discovers its public IP at startup; only the
// optional bootstrap seed is added when a value is supplied.
var baseArgs = [
  '-data=/data'
  '-listen=/ip4/0.0.0.0/tcp/4001'
  '-advertise=true'
  '-capacity=100'
  '-log-format=json'
  '-log-level=info'
  '-metrics=:9096'
  '-quota=1073741824'
  '-geoip=ip-api'
  // The ledger lives in PostgreSQL, so no file share is mounted: /data is the
  // container's ephemeral disk holding only shard blobs and the libp2p identity.
  '-ledger-driver=postgres'
  '-ledger-dsn=${ledgerDsn}'
  '-repair-interval=1h'
  '-rebalance-interval=1h'
]
var bootstrapArgs = empty(seedAddr) ? [] : [ '-bootstrap', seedAddr ]
var containerArgs = concat(baseArgs, bootstrapArgs)

// 1. Network: one subnet delegated to Container Apps, one delegated to the
// PostgreSQL flexible server so the ledger is reachable privately only.
resource vnet 'Microsoft.Network/virtualNetworks@2023-09-01' = {
  name: 'vnet-${resourceToken}'
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.0.0.0/16'
      ]
    }
    subnets: [
      {
        name: 'containerapps'
        properties: {
          addressPrefix: '10.0.0.0/23'
          delegations: [
            {
              name: 'containerapps-delegation'
              properties: {
                serviceName: 'Microsoft.App/environments'
              }
            }
          ]
        }
      }
      {
        name: 'postgres'
        properties: {
          addressPrefix: '10.0.2.0/24'
          delegations: [
            {
              name: 'postgres-delegation'
              properties: {
                serviceName: 'Microsoft.DBforPostgreSQL/flexibleServers'
              }
            }
          ]
        }
      }
    ]
  }
}

// 2. Private DNS zone so the container app resolves the server's private address.
resource postgresDnsZone 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: 'privatelink.postgres.database.azure.com'
  location: 'global'
  tags: tags
}

resource postgresDnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: postgresDnsZone
  name: 'link-${resourceToken}'
  location: 'global'
  tags: tags
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vnet.id
    }
  }
}

// 3. PostgreSQL flexible server: the node's ledger backend.
resource postgres 'Microsoft.DBforPostgreSQL/flexibleServers@2024-08-01' = {
  name: postgresServerName
  location: location
  tags: tags
  sku: {
    name: 'Standard_B1ms'
    tier: 'Burstable'
  }
  properties: {
    version: '16'
    administratorLogin: postgresAdminUser
    administratorLoginPassword: postgresAdminPassword
    storage: {
      storageSizeGB: 32
    }
    backup: {
      backupRetentionDays: 7
      geoRedundantBackup: 'Disabled'
    }
    highAvailability: {
      mode: 'Disabled'
    }
    network: {
      delegatedSubnetResourceId: resourceId('Microsoft.Network/virtualNetworks/subnets', vnet.name, 'postgres')
      privateDnsZoneArmResourceId: postgresDnsZone.id
    }
  }
  dependsOn: [
    postgresDnsLink
  ]

  resource database 'databases' = {
    name: postgresDatabaseName
    properties: {
      charset: 'UTF8'
      collation: 'en_US.utf8'
    }
  }
}

// 4. Log Analytics workspace
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: 'log-${resourceToken}'
  location: location
  tags: tags
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}

// 5. Container App Environment
resource containerEnv 'Microsoft.App/managedEnvironments@2023-11-02-preview' = {
  name: 'cae-${resourceToken}'
  location: location
  tags: tags
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logAnalytics.properties.customerId
        sharedKey: logAnalytics.listKeys().primarySharedKey
      }
    }
    vnetConfiguration: {
      infrastructureSubnetId: resourceId('Microsoft.Network/virtualNetworks/subnets', vnet.name, 'containerapps')
      internal: false
    }
  }
}

// 6. Container App deployment
resource containerApp 'Microsoft.App/containerApps@2023-11-02-preview' = {
  name: 'app-${resourceToken}'
  location: location
  tags: union(tags, { 'azd-service-name': 'node' })
  dependsOn: [
    postgres::database
  ]
  properties: {
    managedEnvironmentId: containerEnv.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        // The primary HTTP ingress receives a managed TLS certificate and
        // redirects HTTP requests to its HTTPS FQDN.
        targetPort: 9096
        transport: 'http'
        // libp2p requires a raw TCP listener and is intentionally not
        // terminated by the HTTP ingress.
        additionalPortMappings: [
          {
            external: true
            exposedPort: 4001
            targetPort: 4001
          }
        ]
      }
    }
    template: {
      containers: [
        {
          name: 'node'
          image: 'ghcr.io/ydethe/revika-node:0.5.11'
          args: containerArgs
        }
      ]
      // The ledger is per-node state: two replicas sharing one database would
      // claim each other's shards. Keep exactly one node per deployment.
      scale: {
        minReplicas: 1
        maxReplicas: 1
      }
    }
  }
}

output AZURE_CONTAINER_APP_ENDPOINT string = containerApp.properties.configuration.ingress.fqdn
output AZURE_POSTGRES_HOST string = postgresFqdn
output AZURE_POSTGRES_DATABASE string = postgresDatabaseName
