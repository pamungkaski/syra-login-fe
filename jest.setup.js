// Learn more: https://github.com/testing-library/jest-dom
import '@testing-library/jest-dom'

// Mock window.crypto for tests
if (typeof window !== 'undefined' && !window.crypto) {
  window.crypto = {
    getRandomValues: (arr) => {
      for (let i = 0; i < arr.length; i++) {
        arr[i] = Math.floor(Math.random() * 256)
      }
      return arr
    }
  }
}

// Mock Buffer for browser environment
if (typeof global !== 'undefined' && !global.Buffer) {
  global.Buffer = require('buffer').Buffer
}

// Silence console during tests except for errors
global.console = {
  ...console,
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
}