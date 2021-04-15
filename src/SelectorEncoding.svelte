<script lang="ts">
    import { Button, Container } from 'svelte-materialify';
    import {encodingDefault} from './store.js';
    import {SignEncoding} from "./enum";
    export let reset = () => {};

    let base64Color;
    let hexColor;

    ($encodingDefault === SignEncoding.Hex) ? setColorsHex(): setColorsBase64();

    function selectHex(){
        reset();
        encodingDefault.set('hex');
        setColorsHex();
    }

    function selectBase64(){
        reset();
        encodingDefault.set('base64');
        setColorsBase64();
    }

    function setColorsHex() {
        base64Color = "grey";
        hexColor = "primary-color";
    }

    function setColorsBase64() {
        base64Color = "primary-color";
        hexColor = "grey";
    }
</script>
<div style="max-width: 700px">
    <Container>
        <Button size="small" class="{hexColor} white-text" on:click={selectHex}>
            Hex
        </Button>
        <Button size="small" class="{base64Color} white-text" on:click={selectBase64}>
            Base64
        </Button>
    </Container>
</div>


