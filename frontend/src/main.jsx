import React from 'react'
import { createRoot } from 'react-dom/client'
import { WalletProvider } from './wallet.js'
import App from './App.jsx'
import './tokens.css'
import './app.css'

createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <WalletProvider>
      <App />
    </WalletProvider>
  </React.StrictMode>,
)
