<script lang="ts">
    import { Alert, Container, Button, Textarea, Icon } from 'svelte-materialify';
    import VerifyEd25519 from './signature'
    import { mdiCheck, mdiAlert } from '@mdi/js';

    export let message;
    export let signature;
    export let publicKey;
    let verify;

    async function performVerify() {
        const ed25519 = new VerifyEd25519(message, signature, publicKey, null);
        verify = await ed25519.check();
    }

    function resetVerify(){
        verify = '';
    }
</script>
<div class="pa-6">
    <div class="pt-6 pb-6" style="max-width: 700px">
        <Container>
            <Textarea outlined rows="2" bind:value={publicKey} on:input={resetVerify}>Public key</Textarea>
            <Textarea outlined rows="2" bind:value={message} on:input={resetVerify}>Message</Textarea>
            <Textarea outlined bind:value={signature} on:input={resetVerify}>Signature</Textarea>
        </Container>
        <Container>
            <Button class="primary-color" on:click={performVerify}>Verify</Button>
        </Container>
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

