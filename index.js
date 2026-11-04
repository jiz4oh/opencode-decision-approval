import { Plugin } from '@opencode/plugin'
import { install } from './src/runtime.js'

export default Plugin.define({
  id: 'opencode-decision-approval',
  setup: install,
})
