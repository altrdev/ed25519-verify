<script lang="ts">
	import FormVerify from './FormVerify.svelte';
	import { MaterialApp, AppBar, Icon, Button } from 'svelte-materialify';
	import { mdiInvertColors } from '@mdi/js';
	import { theme } from './store.js';

	function toggleTheme() {
		if ($theme === 'light') theme.set('dark');
		else theme.set('light');
	}
</script>

<MaterialApp theme={$theme}>
	<AppBar>
		<span slot="title">Ed25519 Verify Signature</span>
		<div style="flex-grow:1"></div>
		<Button icon on:click={toggleTheme}>
			<Icon path={mdiInvertColors}/>
		</Button>
	</AppBar>
	<FormVerify message="" signature="" publicKey=""/>
</MaterialApp>
