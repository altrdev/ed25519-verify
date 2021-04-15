<script lang="ts">
    import {Alert, Container, Button, Textarea, Icon} from 'svelte-materialify';
    import VerifyEd25519 from './signature'
    import {mdiCheck, mdiAlert} from '@mdi/js';
    import SelectorEncoding from "./SelectorEncoding.svelte";
    import {encodingDefault} from "./store";
    import {SignEncoding} from "./enum";

    export let message;
    export let signature;
    export let publicKey;
    let verify;

    async function performVerify() {
        const ed25519 = new VerifyEd25519(message, signature, publicKey, null);
        verify = await ed25519.check($encodingDefault as SignEncoding);
    }

    function resetVerify() {
        verify = '';
    }
</script>
<div class="pa-6">
    <SelectorEncoding reset="{resetVerify}"/>
    <div class="pt-1 pb-6" style="max-width: 700px">
        <Container>
            <Textarea outlined rows="2" bind:value={publicKey} on:input={resetVerify}>Public key</Textarea>
            <Textarea outlined rows="2" bind:value={message} on:input={resetVerify}>Message</Textarea>
            <Textarea outlined bind:value={signature} on:input={resetVerify}>Signature</Textarea>
        </Container>
        <Container>
            <Button class="primary-color" on:click={performVerify}>Verify</Button>
        </Container>
    </div>
    <div class="pb-6" style="max-width: 700px">
        {#if verify}
            <Alert class="success-color">
                <div slot="icon">
                    <Icon path={mdiCheck} />
                </div>
                Signature is valid
            </Alert>
        {:else if verify === false}
            <Alert class="error-color">
                <div slot="icon">
                    <Icon path={mdiAlert} />
                </div>
                Signature is wrong
            </Alert>
        {/if}
    </div>
</div>

