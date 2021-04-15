<script lang="ts">
    import {Alert, Container, Button, Textarea, Icon} from 'svelte-materialify';
    import VerifyEd25519 from './signature'
    import {mdiCheck, mdiAlert} from '@mdi/js';
    import SelectorEncoding from "./SelectorEncoding.svelte";
    import {encodingDefault} from './store.js';
    import {SignEncoding} from "./enum";

    export let message;
    export let privateKey;
    export let signature;
    let publicKey;

    async function performSign() {
        const ed25519 = new VerifyEd25519(message, null, null, privateKey);
        signature = await ed25519.sign($encodingDefault as SignEncoding);
    }

    function reset() {
        signature = '';
    }

    async function deductPublicKey() {
        const ed25519 = new VerifyEd25519(message, null, null, privateKey);
        publicKey = await ed25519.getPublicKey($encodingDefault as SignEncoding);
    }
</script>
<div class="pa-6">
    <SelectorEncoding reset="{reset}"/>
    <div class="pt-1 pb-6" style="max-width: 700px">
        <Container>
            <Textarea outlined rows="2" bind:value={privateKey} on:change={deductPublicKey}>Private key</Textarea>
            <Textarea outlined disabled=true rows="2" bind:value={publicKey} placeholder="Insert private key for deducing ...">Deduced Public key</Textarea>
            <Textarea outlined rows="2" bind:value={message}>Message (Plain text)</Textarea>
        </Container>
        <Container>
            <Button class="primary-color" on:click={performSign}>Sign</Button>
        </Container>

    </div>
    <div class="pb-6" style="max-width: 700px">
        {#if signature == null}
            <Alert class="error-color">
                <div slot="icon">
                    <Icon path={mdiAlert} />
                </div>
                Signature can't be performed. Private key is mandatory
            </Alert>
        {:else if signature !== ''}
            <Alert class="success-color">
                <div slot="icon">
                    <Icon path={mdiCheck} />
                </div>
                Signature:
                <br><br>
                <div class="text-xl-caption font-weight-bold" style="display: table; table-layout: fixed;width: 100%; overflow-wrap: break-word;">{signature}</div>
            </Alert>
        {/if}
    </div>
</div>

