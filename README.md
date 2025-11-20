# API DSM - Backend con Express + Firebase (Render)

## Rutas principales

- POST /auth/register
- POST /auth/login
- GET  /events
- GET  /events/:id
- POST /events/:id/comments
- GET  /events/:id/comments
- POST /attend/:eventId/confirm
- POST /attend/:eventId/cancel
- GET  /attend/:eventId/attendees

## Deploy en Render

Build command:
  npm install

Start command:
  npm start

Variables de entorno:
- FIREBASE_PROJECT_ID
- FIREBASE_CLIENT_EMAIL
- FIREBASE_PRIVATE_KEY  (con \n en los saltos de línea)
- JWT_SECRET
