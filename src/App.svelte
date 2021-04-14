<script lang="ts">
	import FormVerify from './FormVerify.svelte';
	import FormSign from './FormSign.svelte';
	import { MaterialApp, AppBar, Icon, Button, Tabs, Tab, TabContent } from 'svelte-materialify';
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
	<AppBar class="primary-color theme--dark">
		<span slot="title">Ed25519 signature tools</span>
		<div style="flex-grow:1"></div>
		<Button icon on:click={toggleTheme}>
			<Icon path={themeIconToggled}/>
		</Button>
	</AppBar>
	<Tabs  class="primary-text">
		<div slot="tabs">
			<Tab>Verify signature</Tab>
			<Tab>Sign message</Tab>
		</div>
		<TabContent>
			<FormVerify message="" signature="" publicKey=""/>
		</TabContent>
		<TabContent>
			<FormSign message="" signature="" publicKey=""/>
		</TabContent>
	</Tabs>

</MaterialApp>
