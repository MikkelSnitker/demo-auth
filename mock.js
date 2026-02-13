
import {clients} from './dist/infrastructure/stores/stores.js'
clients.set('web-app', {
  id: 'web-app',
  secret: 'web-secret',
  redirectUris: ['http://localhost:3000/callback'],
  scopes: ['openid', 'offline_access'],
  refreshTokenLifetimeSeconds: 60 * 60 * 24 * 30
})
clients.set('spa-client', {
  id: 'spa-client',
  secret: '', // not used
  redirectUris: ['http://localhost:5173/callback'],
  scopes: ['openid', 'offline_access'],
  refreshTokenLifetimeSeconds: 60 * 60 * 24 * 7
})
clients.set('secure-app', {
  id: 'secure-app',
  secret: 'secure-secret',
  redirectUris: ['http://localhost:4001/callback'],
  scopes: ['openid', 'offline_access'],
  refreshTokenLifetimeSeconds: 60 * 60
})
clients.set('backend-service', {
  id: 'backend-service',
  secret: 'backend-secret',
  redirectUris: ['http://localhost:3000/callback'],
  scopes: ['openid', 'offline_access'],
  refreshTokenLifetimeSeconds: 60 * 60 * 24 * 90
})


console.log("Mock clients loaded");