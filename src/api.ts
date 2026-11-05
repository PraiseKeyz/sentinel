import type { SentinelApi } from '../shared/types';
import { mockApi } from './mock';

declare global {
  interface Window {
    sentinel?: SentinelApi;
  }
}

/** The real bridge inside Electron; demo data when the UI is opened in a plain browser. */
export const api: SentinelApi = window.sentinel ?? mockApi();
/** Set by scripts/screenshot.cjs to render clean README images. */
const screenshot = new URLSearchParams(location.search).has('screenshot');
export const isDemo = !window.sentinel && !screenshot;
export const isMac = navigator.userAgent.includes('Mac') && !screenshot;
