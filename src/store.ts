import { writable } from "svelte/store";
import { mdiWeatherNight, mdiWeatherSunny } from '@mdi/js';

const storedTheme = localStorage.getItem("theme");
export const theme = writable(storedTheme);

export const themeIcon = storedTheme === 'dark' ? mdiWeatherSunny : mdiWeatherNight;

theme.subscribe(value => {
    localStorage.setItem("theme", value === 'dark' ? 'dark' : 'light');
});
