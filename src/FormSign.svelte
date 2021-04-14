<script lang="ts">
    import { Alert, Container, Button, Textarea, Icon } from 'svelte-materialify';
    import VerifyEd25519 from './signature'
    import { mdiCheck, mdiAlert } from '@mdi/js';

    export let message;
    export let signature;
    export let publicKey;
    export let privateKey;
    let verify;

    async function performSign() {
        const ed25519 = new VerifyEd25519(message, null, null, privateKey);
        signature = await ed25519.sign();
    }

    function reset(){
        signature = '';
    }
</script>
<div class="pa-6">
    <div class="pt-6 pb-6" style="max-width: 700px">
        <Container>
            <Textarea outlined rows="2" bind:value={privateKey}>Private key</Textarea>
            <Textarea outlined rows="2" bind:value={message}>Message</Textarea>
        </Container>
        <Container>
            <Button class="primary-color" on:click={performSign}>Sign</Button>
        </Container>
        {#if signature == null}
            <Alert class="error-color">
                <div slot="icon">
                    <Icon path={mdiAlert} />
                </div>
                Signature can't be
            </Alert>
        {:else if signature !== ''}
            <Alert class="success-color">
                <div slot="icon">
                    <Icon path={mdiCheck} />
                </div>
                Signature: {signature}
            </Alert>
        {/if}
    </div>
</div>

