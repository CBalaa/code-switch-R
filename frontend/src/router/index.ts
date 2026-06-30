import { createRouter, createWebHashHistory } from 'vue-router'
import MainPage from '../components/Main/Index.vue'

const routes = [
  { path: '/', component: MainPage },
  { path: '/logs', component: () => import('../components/Logs/Index.vue') },
  { path: '/console', component: () => import('../components/Console/Index.vue') },
  { path: '/keys', component: () => import('../components/Keys/Index.vue') },
  { path: '/settings', component: () => import('../components/General/Index.vue') },
  { path: '/tray', component: () => import('../components/Tray/Index.vue') },
]

export default createRouter({
  history: createWebHashHistory(), // Use createWebHashHistory for hash-based routing
  routes
})
