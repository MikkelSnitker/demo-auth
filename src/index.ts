import { startServer } from './http/server.js'
const server = startServer()
server.listen(4000, () => {
  console.log('OAuth Strict Server running at http://localhost:4000')
})
