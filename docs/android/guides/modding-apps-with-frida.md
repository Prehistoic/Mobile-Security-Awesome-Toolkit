# Modding and Distributing Mobile Apps with Frida

**Source:** https://pit.bearblog.dev/modding-and-distributing-mobile-apps-with-frida/

[Frida](../tools/frida.md) is most often used in its *no-bs* mode, with a host machine plugged via USB to a rooted phone. However it also supports autonomous script execution, which is ideal for modding.

- [1. Create the Agent](#1-create-the-agent)
- [2. Mod Development](#2-mod-development)
- [3. Mod Distibution](#3-mod-distibution)
  - [Notes for Split APKs](#notes-for-split-apks)

## 1. Create the Agent

The `frida-tools` Python package contains a script to scaffold a new frida agent:

```sh
> frida-create -t agent -o mod
Created mod/package.json
Created mod/tsconfig.json
Created mod/agent/index.ts
Created mod/agent/logger.ts
Created mod/.gitignore

Run `npm install` to bootstrap, then:
- Keep one terminal running: npm run watch
- Inject agent using the REPL: frida Calculator -l _agent.js
- Edit agent/*.ts - REPL will live-reload on save
```

This creates a new Typescript project, configured with all the correct switches and scripts that will allow us to compile frida agents with `npm run build`

## 2. Mod Development

1. **Install the bridge package**

```sh
npm install frida-java-bridge
```

2. **Create mod**, for example :

```js
// _agent.js
import Java from "frida-java-bridge";

Java.perform(function() {
    var dicer = Java.use("org.secuso.privacyfriendlydicer.dicer.Dicer");

    dicer.rollDice.implementation = function (numDice: number, numFaces: number) {
        return Array(numDice).fill(1);
    };
});
```

3. **Compile frida agent**

```sh
npm run build
```

4. **Test the mod**

```sh
frida -U -f org.secuso.privacyfriendlydicer -l _agent.js
```

## 3. Mod Distibution

Frida requires an agent to be injected in the target process in order to instrument the app. Usually this is done by using `frida-server` on a rooted device.

However we can also use the dynamic library `frida-gadget` (which can be embedded directly in the app) to achieve the same thing, even on unrooted devices.

1. **Create the `frida-gadget` configuration file**

```json
// gadget-config.json
{
    "interaction": {
        "type": "script",
        "path": "libfrida-gadget.script.so"
    }
}
```

2. **Patch the APK with [Objection](../../common/tools/objection.md)**

```sh
objection patchapk -s org.secuso.privacyfriendlydicer.apk -c gadget-config.js -l mod/_agent.js --use-aapt2
```

You should now have a file named `<original_apk_name>.objection.apk` in the current directory. That's the modded APK !

### Notes for Split APKs

- Make sure to mod the base APK (the one containing the `MainActivity` of the app)
- Sign other split APKs with the same key that `objection` used : 

```sh
objection signapk apk1, apk2, ...
```

- Install the split APKs together OR use [APKEditor](https://github.com/REAndroid/APKEditor) to merge them into a single one for distribution !

```sh
adb install-multiple apk1, apk2, ...
# OR
java -jar APKEditor.jar m -i /path/to/splitapks_dir
```

