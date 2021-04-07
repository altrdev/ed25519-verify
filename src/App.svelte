<script lang="ts">
	import FormVerify from './FormVerify.svelte';
	import { MaterialApp, AppBar, Icon, Button } from 'svelte-materialify';
	import { mdiInvertColors } from '@mdi/js';

	export let theme: "light" | "dark";

	function toggleTheme() {
		if (theme === 'light') theme = 'dark';
		else theme = 'light';
	}
</script>

<MaterialApp {theme}>
	<AppBar>
		<span slot="title">Ed25519 Verify Signature</span>
		<div style="flex-grow:1" />
		<Button icon on:click={toggleTheme}>
			<Icon path={mdiInvertColors}/>
		</Button>
	</AppBar>
	<FormVerify/>
</MaterialApp>
