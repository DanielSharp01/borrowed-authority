# Prototype pollution: practical exploitability and a Zod boundary

Research date: 2026-09-11

## Short answer

Prototype pollution is a real vulnerability class. The pollution operation is not usually the final exploit, though. A useful attack needs two independent pieces:

1. A pollution source lets attacker-controlled property names reach an unsafe deep setter, path traversal, parser, or recursive merge.
2. A gadget later reads an inherited property and gives that value security meaning.

If we count the decisions inside the source separately, the chain contains three mistakes:

1. The API exposes a generic property path where a business-specific field would do.
2. The setter or merger traverses `__proto__`, `constructor`, or `prototype` without blocking them.
3. Authorization, request construction, template compilation, or another sensitive operation trusts an inherited property.

The first two often live inside one generic helper, so I would describe this on stage as **two independent defects, with the first defect made from two bad decisions**. An attacker also needs access to the affected input route and a value that fits the later gadget. Those are prerequisites, not necessarily developer mistakes.

This distinction matters. Polluting `Object.prototype.demo = true` proves a write. It does not prove account takeover, cross-site scripting, or code execution. The application still needs to consume `demo` in a useful way. MDN describes the same two phases as pollution followed by exploitation. [MDN: JavaScript prototype pollution](https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/Prototype_pollution#anatomy_of_prototype_pollution)

There is unusually good current evidence that this is not just a lab trick. ApostropheCMS published a critical advisory in 2026 for almost exactly this pattern. An editor-controlled dot path reached `apos.util.set()`, wrote `publicApiProjection` to `Object.prototype`, and a later authorization check inherited that truthy value and skipped its access check for subsequent unauthenticated requests. [ApostropheCMS GHSA-6h5j-32cf-4253](https://github.com/apostrophecms/apostrophe/security/advisories/GHSA-6h5j-32cf-4253)

## The mechanics

Ordinary JavaScript objects inherit from `Object.prototype`. If an object has no own property with a requested name, lookup continues through its prototype chain. [ECMAScript overview of objects and prototypes](https://tc39.es/ecma262/multipage/overview.html#sec-objects)

The legacy `Object.prototype.__proto__` property is an accessor. Reading it exposes an object's prototype and assigning to it can change that object's prototype. It is deprecated, but remains for web compatibility. [ECMAScript `Object.prototype.__proto__`](https://tc39.es/ecma262/multipage/fundamental-objects.html#sec-object.prototype.__proto__) [MDN `Object.prototype.__proto__`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto)

The other important route is `constructor.prototype`. For a normal object, `obj.constructor` usually resolves to `Object`, and `obj.constructor.prototype` reaches `Object.prototype`. This is why a filter that blocks only `__proto__` is incomplete. [MDN pollution sources](https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/Prototype_pollution#pollution_sources)

A minimal unsafe setter makes the problem visible:

```ts
function setPath(target: object, path: string[], value: unknown) {
  let cursor: any = target;

  for (const segment of path.slice(0, -1)) {
    cursor = cursor[segment] ??= {};
  }

  cursor[path.at(-1)!] = value;
}

setPath({}, ["__proto__", "isAdmin"], true);

console.log(({} as { isAdmin?: boolean }).isAdmin);
// true
```

On the first segment, `cursor["__proto__"]` resolves to `Object.prototype`. The last assignment therefore adds `isAdmin` to the shared prototype. GitHub's CodeQL documentation identifies unsafe recursive copy and deep assignment helpers as common pollution sources and recommends guarding inside the helper. [CodeQL: prototype-polluting function](https://codeql.github.com/codeql-query-help/javascript/js-prototype-pollution-utility/)

The same effect is possible through `constructor.prototype`:

```ts
setPath({}, ["constructor", "prototype", "isAdmin"], true);
```

## What turns pollution into an exploit

The easiest useful gadgets read a missing property as though it were an explicit value:

```ts
function mayOpenAdmin(user: { id: string; isAdmin?: boolean }) {
  if (user.isAdmin) {
    return "admin dashboard";
  }

  return "access denied";
}
```

After the pollution above, a normal object such as `{ id: "attacker" }` inherits `isAdmin: true`. The check never asks whether `isAdmin` is an own property.

Real gadgets tend to fall into these groups:

- Authorization and feature gates that treat a missing flag as false, then accept any inherited truthy value.
- Configuration objects passed to HTTP clients, template engines, sanitizers, DOM APIs, or process-launching code.
- Loops or conversions that assume inherited values have a particular type, which often produces denial of service.

Impact is not equally difficult at every level:

- Process errors and denial of service are comparatively easy. A polluted value of the wrong type can break unrelated requests.
- Authorization bypass needs a matching boolean or configuration-property gadget.
- Code execution normally needs another dangerous operation that interprets attacker-controlled data as code, a command, a module, or process configuration. JSON cannot directly carry a function, getter, or proxy, so claims that put an attacker-supplied function straight into `Object.prototype` need a second in-process capability beyond plain JSON.

This is one reason remote code execution demonstrations can look contrived while authorization bypasses do not. The ApostropheCMS case needed only a truthy array and an inherited option. No attacker-supplied function was necessary. [ApostropheCMS advisory details and proof](https://github.com/apostrophecms/apostrophe/security/advisories/GHSA-6h5j-32cf-4253#details)

Other first-party advisories show the range of practical impact:

- n8n documented a workflow import/update path that let a user with normal workflow creation rights pollute `Object.prototype`. The resulting gadget bypassed authentication and exposed user and project information to unauthenticated callers. [n8n GHSA-75qm-gp28-rcq9](https://github.com/n8n-io/n8n/security/advisories/GHSA-75qm-gp28-rcq9)
- Trigger.dev documented a metadata path setter that caused process-wide, cross-tenant failures and a crash loop. A normal environment API key was enough to reach it. [Trigger.dev GHSA-p28v-f755-9qrg](https://github.com/triggerdotdev/trigger.dev/security/advisories/GHSA-p28v-f755-9qrg)
- Axios documented read-side gadgets that could reroute outbound requests through a polluted `proxy` option and expose authorization headers. Axios was the gadget in that advisory, not the original pollution source. [Axios GHSA-mmx7-hfxf-jppx](https://github.com/axios/axios/security/advisories/GHSA-mmx7-hfxf-jppx)

There are also cases where a vulnerable dependency did not establish a product exploit. Elastic's 2019 advisory for Lodash prototype pollution said no exploitable Kibana path had been identified when it was published. That is a useful counterexample to treating every pollution primitive as a completed exploit. [Elastic ESA-2019-10](https://discuss.elastic.co/t/elastic-stack-6-8-2-and-7-2-1-security-update/192963)

## JSON, assignment, spread, and merging

`JSON.parse()` does not pollute a prototype merely because the JSON contains `"__proto__"`. The result has an own data property with that name. The danger starts when later code treats that property as a path or copies it with assignment semantics. [MDN on JSON and prototype pollution](https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/Prototype_pollution#pollution_sources) [ECMAScript `JSON.parse`](https://tc39.es/ecma262/multipage/structured-data.html#sec-json.parse)

```ts
const input = JSON.parse('{"__proto__":{"isAdmin":true}}');

Object.hasOwn(input, "__proto__");
// true

({} as { isAdmin?: boolean }).isAdmin;
// undefined
```

`Object.assign(target, input)` is different. The ECMAScript algorithm copies each source key using `Set` on the target. For `__proto__`, that can invoke the inherited setter and replace the target object's prototype. It commonly changes the prototype of that one target rather than writing to global `Object.prototype`, but the target can still become exploitable. [ECMAScript `Object.assign`](https://tc39.es/ecma262/multipage/fundamental-objects.html#sec-object.assign)

```ts
const options = Object.assign(
  { operation: "read" },
  JSON.parse('{"__proto__":{"isAdmin":true}}'),
);

options.isAdmin;
// true, inherited from the replacement prototype
```

Object spread uses `CopyDataProperties`, which creates own data properties instead of assigning through an inherited setter. A shallow spread therefore does not trigger the `__proto__` setter in this case. [ECMAScript `CopyDataProperties`](https://tc39.es/ecma262/multipage/abstract-operations.html#sec-copydataproperties)

```ts
const options = {
  operation: "read",
  ...JSON.parse('{"__proto__":{"isAdmin":true}}'),
};

Object.getPrototypeOf(options) === Object.prototype;
// true

Object.hasOwn(options, "__proto__");
// true
```

Spread is not a general prototype-pollution sanitizer. It is shallow. It preserves an own `__proto__` data property, and it does not make a later deep setter safe. It also does nothing about a path string such as `"constructor.prototype.isAdmin"`.

Unsafe recursive merge code is more dangerous than either shallow operation. It can recursively follow `target[key]` into a shared prototype, then write into it. `for...in` also enumerates inherited enumerable properties, while `Object.keys()` and `Object.entries()` restrict enumeration to own properties. The safest generic containers for untrusted keys are `Map` or null-prototype objects. [MDN defense checklist](https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/Prototype_pollution#defense_summary_checklist)

## What Zod prevents

A closed, business-shaped Zod schema can stop the attack before the unsafe helper sees it. Two details are load-bearing:

1. Constrain property names or paths to the small set the operation really supports.
2. Pass the parsed output onward. Calling `.parse()` and then continuing to use `req.body` throws the protection away.

Zod's current documentation says `z.object()` strips unknown keys from its parsed result. `z.strictObject()` rejects unknown keys. `z.looseObject()` allows them, and `.catchall()` validates otherwise unknown keys with a supplied schema. [Zod object schemas](https://zod.dev/api#objects)

Zod also documents that `.parse()` returns a deep clone rather than merely blessing the original reference. [Zod basic usage](https://zod.dev/basics#parsing-data)

A compact safe boundary looks like this:

```ts
import * as z from "zod";

const PreferencePatch = z.strictObject({
  path: z.enum(["profile.theme", "profile.locale"]),
  value: z.string(),
});

app.patch("/preferences", (req, res) => {
  const patch = PreferencePatch.parse(req.body);

  setPath(preferences, patch.path.split("."), patch.value);
  res.sendStatus(204);
});
```

`__proto__.isAdmin` and `constructor.prototype.isAdmin` both fail at `z.enum`. The helper remains generic, but untrusted input can no longer select arbitrary traversal segments.

For most application endpoints, an even better shape removes paths altogether:

```ts
const PreferencePatch = z.strictObject({
  theme: z.enum(["light", "dark"]).optional(),
  locale: z.enum(["en", "de", "hu"]).optional(),
});

const patch = PreferencePatch.parse(req.body);
Object.assign(preferences, patch);
```

There is no property language for an attacker to program. The payload has to look like the business operation.

### The misleading Zod example

This validates the outer shape but does not stop prototype pollution:

```ts
const Patch = z.strictObject({
  path: z.string(),
  value: z.unknown(),
});
```

`path` is expected, so strictness says nothing about its contents. `"__proto__.isAdmin"` is a valid string and `true` is valid unknown data. The schema must validate the meaning of the path with an enum or a refinement.

The same warning applies to broad schemas:

- Zod 3's `.passthrough()` and Zod 4's `z.looseObject()` are permissive modes for unknown keys. Current Zod has special handling for `__proto__`, but permissive mode still is not a business allowlist.
- `.catchall(z.unknown())` validates extra values but does not make their names part of a business allowlist. Current Zod's `__proto__` guard still applies.
- `z.record(z.string(), valueSchema)` accepts arbitrary string keys. If the set is finite, Zod supports an enum as the record key schema.
- A nested property declared as `z.unknown()` or `z.record(z.string(), z.unknown())` can carry attacker-controlled structure into a later deep setter.

The Zod record documentation confirms that record keys have their own schema and shows enum-constrained records. [Zod records](https://zod.dev/api#records)

### Zod version history and reserved-key caveats

Zod itself has needed prototype-pollution hardening. This is worth mentioning if the slide risks sounding like "install Zod and forget about it."

- A 2023 Zod issue demonstrated that `z.record(z.object(...))` could produce an output whose prototype supplied an attacker-controlled value. [Zod issue #2227](https://github.com/colinhacks/zod/issues/2227)
- Zod 4.4.0 changed object catchall paths to skip `__proto__`. [Zod 4.4.0 release notes](https://github.com/colinhacks/zod/releases/tag/v4.4.0)
- In Zod 4.4.3, `z.strictObject()` safely dropped an own `__proto__` input key but mistakenly reported the parse as successful instead of rejecting the unknown key. The output prototype remained intact. [Zod issue #6220](https://github.com/colinhacks/zod/issues/6220)
- The reporting bug was fixed in merged PR #6221. Releases containing that fix report an undeclared own `__proto__` key as unrecognized and still refuse to copy it into the result. [Zod PR #6221](https://github.com/colinhacks/zod/pull/6221)

The practical guidance is simple. Use a maintained Zod release, use a closed schema at trust boundaries, constrain dynamic keys semantically, and use the parsed result. Do not claim that every historical Zod version or every Zod schema is a pollution barrier.

Zod prevents attacker input from becoming a new pollution source. It does not repair an `Object.prototype` that some earlier code already polluted. Parsed objects are still ordinary objects, so explicit defaults and own-property checks remain valuable around sensitive decisions.

## Defenses outside validation

Validation is the cleanest defense for an application endpoint, but the generic helper should also defend itself. A reusable deep setter cannot know the application's business allowlist, but it can refuse every `__proto__`, `constructor`, and `prototype` path segment. ApostropheCMS adopted exactly this repair in its 4.31.0 release. [ApostropheCMS 4.31.0 security notes](https://github.com/apostrophecms/apostrophe/discussions/5474)

Other useful controls are:

- Use `Map` for attacker-controlled keys, or `Object.create(null)` when an object is necessary.
- Use `Object.hasOwn(value, key)` before trusting a sensitive optional property.
- Give security-sensitive options explicit own defaults such as `isAdmin: false`.
- Avoid `for...in` for untrusted dictionaries.
- Freeze built-in prototypes in tightly controlled runtimes after polyfills load, if compatibility permits.
- Run Node with `--disable-proto=throw` or `--disable-proto=delete` as defense in depth.

Node's flag disables only `Object.prototype.__proto__`. It does not stop `constructor.prototype` traversal, so it cannot replace path validation. [Node.js `--disable-proto`](https://nodejs.org/api/cli.html#--disable-protomode)

## A safe local demonstration

Keep the demo data-only and clean up in `finally`. Do not use `child_process`, network callbacks, or a persistent development server process.

```ts
function setPath(target: object, path: string[], value: unknown) {
  let cursor: any = target;
  for (const segment of path.slice(0, -1)) {
    cursor = cursor[segment] ??= {};
  }
  cursor[path.at(-1)!] = value;
}

try {
  const attackerInput = {
    path: ["__proto__", "isAdmin"],
    value: true,
  };

  setPath({}, attackerInput.path, attackerInput.value);

  const ordinaryUser: { id: string; isAdmin?: boolean } = {
    id: "attacker",
  };
  console.log(ordinaryUser.isAdmin); // true, inherited
  console.log(Object.hasOwn(ordinaryUser, "isAdmin")); // false
} finally {
  delete (Object.prototype as { isAdmin?: boolean }).isAdmin;
}
```

Run it in a short-lived Node process if demonstrating live. The `finally` cleanup makes reruns predictable, but process isolation is better because a failed or interrupted demo cannot leave the presentation runtime polluted.

## Recommended three-slide specialty sequence

### Slide 1: "Prototype pollution: real vulnerability or JavaScript party trick?"

Start with the oddity:

```ts
setPath({}, ["__proto__", "isAdmin"], true);
({}).isAdmin; // true
```

Then refuse to call that an exploit yet. Reveal this equation:

```text
attacker-controlled path
        +
unsafe prototype traversal
        +
security-sensitive inherited read
        =
real impact
```

Speaker point: "The first two lines create a pollution source. The last line is the gadget. We need both defects."

### Slide 2: "What does exploitation actually take?"

Use a compact forward chain, not another large chain diagram:

```text
PATCH path: __proto__.isAdmin
        ↓
generic setPath()
        ↓
Object.prototype.isAdmin = true
        ↓
if (user.isAdmin)
        ↓
authorization bypass
```

Reveal the source code on the left and the later authorization read on the right. Add a small factual footer: "This shape caused a critical ApostropheCMS authorization bypass in 2026." Link the advisory in speaker notes. The real advisory used `publicApiProjection`, not `isAdmin`, so say that the demo changes the property name for clarity.

This slide answers the main question honestly. A denial-of-service gadget may be easier. Remote code execution is harder because the application needs a further code-interpreting gadget. The clean authorization example proves practical severity without a contrived shell payload.

### Slide 3: "One boring schema breaks the exploit"

Show the inadequate schema first:

```ts
z.strictObject({
  path: z.string(),
  value: z.unknown(),
});
```

Then replace two types:

```ts
const Patch = z.strictObject({
  path: z.enum(["profile.theme", "profile.locale"]),
  value: z.string(),
});

const patch = Patch.parse(req.body);
setPath(settings, patch.path.split("."), patch.value);
```

The reveal should mark both the malicious `__proto__` and `constructor.prototype` paths as rejected. End with one sentence:

> Validate the operation's meaning, then use the parsed value.

Speaker caveat: `strictObject` rejects extra object keys, but it cannot know that a string inside an allowed `path` field is dangerous. The enum is what makes this example decisive.

## Suggested conclusion for the presentation

Prototype pollution is less like SQL injection and more like a two-stage trust failure. One part lets data rewrite inheritance. Another part mistakes inherited state for an explicit security decision. That makes spectacular exploits less automatic than the name suggests, but real authorization bypasses and process-wide failures prove it is not theoretical.

The satisfying lesson for this deck is that the exotic JavaScript bug dies at a very ordinary boundary. Replace a programmable property path with a business-shaped schema, reject unknown structure, and pass only the parsed output onward.
