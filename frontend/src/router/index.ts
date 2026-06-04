import { createRouter, createWebHashHistory } from 'vue-router'
import MainPage from '../components/Main/Index.vue'
import LogsPage from '../components/Logs/Index.vue'
import GeneralPage from '../components/General/Index.vue'
import ConsolePage from '../components/Console/Index.vue'
import TrayPage from '../components/Tray/Index.vue'
import KeysPage from '../components/Keys/Index.vue'

const routes = [
  { path: '/', component: MainPage },
  { path: '/logs', component: LogsPage },
  { path: '/console', component: ConsolePage },
  { path: '/keys', component: KeysPage },
  { path: '/settings', component: GeneralPage },
  { path: '/tray', component: TrayPage },
]

export default createRouter({
  history: createWebHashHistory(), // Use createWebHashHistory for hash-based routing
  routes
})
