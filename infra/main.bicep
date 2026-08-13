targetScope = 'resourceGroup'

@minLength(1)
@maxLength(64)
@description('Name of the environment which is used to generate a short unique hash for resources.')
param environmentName string

@minLength(1)
@description('Primary location for all resources')
param location string = resourceGroup().location

param seedAddr string = ''
param publicIp string = ''

var resourceToken = toLower(uniqueString(subscription().id, environmentName, location))
var tags = { 'azd-env-name': environmentName }

// Node command line. Optional flags (public IP, bootstrap seed) are only added
// when a value is supplied, so an unset azd env var never injects a broken flag.
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
  // The ledger journal mode defaults to "delete" (a rollback journal), which is
  // required on this Azure Files NFS /data mount because SQLite WAL needs a
  // shared-memory mapping a network filesystem cannot provide. Pass
  // -ledger-journal=wal here only if the mount is ever moved to local disk.
]
var publicIpArgs = empty(publicIp) ? [] : [ '-public-ip=${publicIp}' ]
var bootstrapArgs = empty(seedAddr) ? [] : [ '-bootstrap', seedAddr ]
var containerArgs = concat(baseArgs, publicIpArgs, bootstrapArgs)

// 1. Network required by Container Apps and Azure Files NFS.
resource nfsNsg 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: 'nsg-${resourceToken}'
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'allow-nfs-outbound'
        properties: {
          priority: 100
          access: 'Allow'
          direction: 'Outbound'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '2049'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: 'Storage'
        }
      }
    ]
  }
}

resource nfsVnet 'Microsoft.Network/virtualNetworks@2023-09-01' = {
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
          serviceEndpoints: [
            {
              service: 'Microsoft.Storage'
            }
          ]
          delegations: [
            {
              name: 'containerapps-delegation'
              properties: {
                serviceName: 'Microsoft.App/environments'
              }
            }
          ]
          networkSecurityGroup: {
            id: nfsNsg.id
          }
        }
      }
    ]
  }
}

// 2. Premium Azure Files account and NFS share for the persistent /data volume.
resource storage 'Microsoft.Storage/storageAccounts@2022-09-01' = {
  name: 'st${resourceToken}'
  location: location
  kind: 'FileStorage'
  sku: { name: 'Premium_LRS' }
  tags: tags
  properties: {
    supportsHttpsTrafficOnly: false
    minimumTlsVersion: 'TLS1_2'
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'AzureServices'
      virtualNetworkRules: [
        {
          action: 'Allow'
          id: resourceId('Microsoft.Network/virtualNetworks/subnets', nfsVnet.name, 'containerapps')
        }
      ]
    }
  }

  resource fileServices 'fileServices' = {
    name: 'default'
    resource share 'shares' = {
      name: 'revikadata'
      properties: {
        shareQuota: 100 // Premium NFS classic shares require at least 100 GiB.
        enabledProtocols: 'NFS'
      }
    }
  }
}

// 3. Log Analytics workspace
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: 'log-${resourceToken}'
  location: location
  tags: tags
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}

// 4. Container App Environment
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
      infrastructureSubnetId: resourceId('Microsoft.Network/virtualNetworks/subnets', nfsVnet.name, 'containerapps')
      internal: false
    }
  }
}

// 5. Attach the NFS storage mount to the environment.
resource envStorage 'Microsoft.App/managedEnvironments/storages@2023-11-02-preview' = {
  parent: containerEnv
  name: 'revikadata'
  properties: {
    nfsAzureFile: {
      server: '${storage.name}.${environment().suffixes.storage}'
      shareName: '/${storage.name}/${storage::fileServices::share.name}'
      accessMode: 'ReadWrite'
    }
  }
}

// 6. Container App deployment (depends explicitly on storage mount being ready)
resource containerApp 'Microsoft.App/containerApps@2023-11-02-preview' = {
  name: 'app-${resourceToken}'
  location: location
  tags: union(tags, { 'azd-service-name': 'node' })
  dependsOn: [
    envStorage
  ]
  properties: {
    managedEnvironmentId: containerEnv.id
    configuration: {
      // Single-revision mode. NOTE: this does NOT serialize writers across a
      // rollout. Container Apps does a *rolling* update even in Single mode — it
      // starts the new revision's replica and only deactivates the old one once
      // the new one is healthy. During that window BOTH replicas mount this
      // Azure Files /data share and open the single-writer SQLite ledger, so the
      // new node's startup migration cannot get the exclusive COMMIT lock and
      // dies with "database is locked (SQLITE_BUSY)". The new replica then
      // crash-loops (never healthy), the old revision is never torn down, and the
      // rollout deadlocks. minReplicas=maxReplicas=1 prevents scale-out
      // concurrency but NOT this revision overlap.
      //
      // Operational rule for a redeploy: free the ledger before the new revision
      // migrates by deactivating the previous revision first, e.g.
      //   az containerapp revision list -n <app> -g <rg> \
      //     --query "[?properties.active].name" -o tsv
      //   az containerapp revision deactivate -n <app> -g <rg> --revision <old>
      //   az containerapp revision restart    -n <app> -g <rg> --revision <new>
      // (Durable alternative: move the ledger DB off the shared NFS mount onto
      // per-node block storage; SQLite on Azure Files is single-writer-only.)
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        targetPort: 4001
        transport: 'auto'
      }
    }
    template: {
      containers: [
        {
          name: 'node'
          image: 'ghcr.io/ydethe/revika-node:0.5.8'
          args: containerArgs
          volumeMounts: [
            {
              volumeName: 'revika-data'
              mountPath: '/data'
            }
          ]
        }
      ]
      volumes: [
        {
          name: 'revika-data'
          storageType: 'NfsAzureFile'
          storageName: 'revikadata'
        }
      ]
      // The node ledger is a single-writer SQLite DB on the shared AzureFile
      // mount: a second replica opening it deadlocks on SQLITE_BUSY. Pin to
      // exactly one replica so a running revision has only one ledger writer.
      // (This does not cover the cross-revision overlap during a rollout — see
      // the activeRevisionsMode note above.)
      scale: {
        minReplicas: 1
        maxReplicas: 1
      }
    }
  }
}

output AZURE_CONTAINER_APP_ENDPOINT string = containerApp.properties.configuration.ingress.fqdn
