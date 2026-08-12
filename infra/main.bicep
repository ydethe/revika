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
          args: [
            '-data=/data'
            '-listen=/ip4/0.0.0.0/tcp/4001'
            '-public-ip=${publicIp}'
            '-advertise=true'
            '-capacity=100'
            '-log-format=json'
            '-log-level=info'
            '-metrics=:9096'
            '-quota=1GB'
            '-geoip=ip-api'
            '-bootstrap'
            seedAddr
          ]
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
    }
  }
}

output AZURE_CONTAINER_APP_ENDPOINT string = containerApp.properties.configuration.ingress.fqdn
