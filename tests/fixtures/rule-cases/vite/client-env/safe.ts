// SAFE: only public, non-secret values are read from import.meta.env.
export const apiUrl = import.meta.env.VITE_PUBLIC_API_URL;
export const appMode = import.meta.env.MODE;
export const isDev = import.meta.env.DEV;
export const baseUrl = import.meta.env.BASE_URL;
export const analyticsId = import.meta.env.VITE_ANALYTICS_ID;
