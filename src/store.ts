import { writable } from "svelte/store";
import { mdiWeatherNight, mdiWeatherSunny } from '@mdi/js';

const storedTheme = localStorage.getItem("theme") ?? 'light';
const storedEncoding = localStorage.getItem("encoding") ?? 'base64';
export const theme = writable(storedTheme);
export const themeIcon = storedTheme === 'dark' ? mdiWeatherSunny : mdiWeatherNight;
export const encodingDefault = writable(storedEncoding);

theme.subscribe(value => {
    localStorage.setItem("theme", value === 'dark' ? 'dark' : 'light');
});

encodingDefault.subscribe(value => {
    localStorage.setItem("encoding", value === 'hex' ? 'hex' : 'base64');
});
