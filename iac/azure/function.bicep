param location string = resourceGroup().location
param modelHash string

resource plan 'Microsoft.Web/serverfarms@2022-09-01' = {
  name: 'sas-plan'
  location: location
  sku: {
    name: 'Y1'
    tier: 'Dynamic'
  }
}

resource fn 'Microsoft.Web/sites@2022-09-01' = {
  name: 'sas-inference'
  location: location
  kind: 'functionapp'
  properties: {
    serverFarmId: plan.id
    siteConfig: {
      appSettings: [
        { name: 'SAS_EXPECTED_MODEL_HASH', value: modelHash }
        { name: 'SAS_RETURN_CONFIDENCE', value: 'false' }
        { name: 'FUNCTIONS_WORKER_RUNTIME', value: 'python' }
      ]
    }
  }
}
