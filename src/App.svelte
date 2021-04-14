<script lang="ts">
	import FormVerify from './FormVerify.svelte';
	import { MaterialApp, AppBar, Icon, Button } from 'svelte-materialify';

	import { theme, themeIcon } from './store.js';
	import { mdiWeatherNight, mdiWeatherSunny } from "@mdi/js";

	let themeIconToggled = themeIcon;

	function toggleTheme() {
		if ($theme === 'light') {
			theme.set('dark');
			themeIconToggled = mdiWeatherSunny;
		}
		else {
			theme.set('light');
			themeIconToggled = mdiWeatherNight;
		}
	}
</script>

<MaterialApp theme={$theme}>
	<AppBar>
		<span slot="title">Ed25519 Verify Signature</span>
		<div style="flex-grow:1"></div>
		<Button icon on:click={toggleTheme}>
			<Icon path={themeIconToggled}/>
		</Button>
	</AppBar>
	<FormVerify message="" signature="" publicKey=""/>
</MaterialApp>
