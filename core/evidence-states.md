# Evidence States

Keep evidence states separate. Do not collapse one state into another.

| State | Meaning |
|---|---|
| Structure verification | The file, schema, object, or interface shape is valid. |
| Runtime verification | The system ran in the target local runtime. |
| Provider smoke | A remote provider path ran under an explicit gate. |
| Human acceptance | The owner or target user accepted the result. |
| Business validation | Market, customer, pricing, distribution, or ROI evidence supports the claim. |
| Durable memory promotion | Evidence-derived scoped memory passed provenance, held-out, expiry, and exact human approval gates. |
| Active rule promotion | A rule candidate passed isolated held-out evaluation and a separate exact human promotion approval. |

Every closeout should state what was verified, what remains unverified, and
which evidence state was reached.
