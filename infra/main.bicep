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
  // required on this Azure Files (SMB) /data mount because SQLite WAL needs a
  // shared-memory mapping a network filesystem cannot provide. Pass
  // -ledger-journal=wal here only if the mount is ever moved to local disk.
]
var publicIpArgs = empty(publicIp) ? [] : [ '-public-ip=${publicIp}' ]
var bootstrapArgs = empty(seedAddr) ? [] : [ '-bootstrap', seedAddr ]
var containerArgs = concat(baseArgs, publicIpArgs, bootstrapArgs)

// 1. Storage Account for persistent /data volume (1 GiB)
resource storage 'Microsoft.Storage/storageAccounts@2022-09-01' = {
  name: 'st${resourceToken}'
  location: location
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  tags: tags
  properties: {
    supportsHttpsTrafficOnly: true
  }

  resource fileServices 'fileServices' = {
    name: 'default'
    resource share 'shares' = {
      name: 'revikadata'
      properties: {
        shareQuota: 1 // 1 GiB storage limit
      }
    }
  }
}

// 2. Log Analytics workspace
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: 'log-${resourceToken}'
  location: location
  tags: tags
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}

// 3. Container App Environment
resource containerEnv 'Microsoft.App/managedEnvironments@2023-05-01' = {
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
  }
}

// 4. Attach Storage Mount to Environment
resource envStorage 'Microsoft.App/managedEnvironments/storages@2023-05-01' = {
  parent: containerEnv
  name: 'revikadata'
  properties: {
    azureFile: {
      accountName: storage.name
      accountKey: storage.listKeys().keys[0].value
      shareName: storage::fileServices::share.name
      accessMode: 'ReadWrite'
    }
  }
}

// 5. Container App deployment (depends explicitly on storage mount being ready)
resource containerApp 'Microsoft.App/containerApps@2023-05-01' = {
  name: 'app-${resourceToken}'
  location: location
  tags: union(tags, { 'azd-service-name': 'node' })
  dependsOn: [
    envStorage
  ]
  properties: {
    managedEnvironmentId: containerEnv.id
    configuration: {
      // Single-revision mode: a new rollout deactivates the previous revision
      // before the next takes over, so two replicas never hold the single-writer
      // ledger at once.
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
          image: 'ghcr.io/ydethe/revika-node:latest'
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
          storageType: 'AzureFile'
          storageName: 'revikadata'
        }
      ]
      // The node ledger is a single-writer SQLite DB on the shared AzureFile
      // mount: a second replica opening it would deadlock on SQLITE_BUSY. Pin
      // to exactly one replica so there is only ever one ledger writer.
      scale: {
        minReplicas: 1
        maxReplicas: 1
      }
    }
  }
}

output AZURE_CONTAINER_APP_ENDPOINT string = containerApp.properties.configuration.ingress.fqdn
