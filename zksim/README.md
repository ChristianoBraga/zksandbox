# Zero Knowledge Protocol Simulator

Essentially, `zksim` implements a multiparty model on top of Lurk.
One may chose to be the prover, the verifier or someone in the public.
One a party is chosen, some commands may or may not be avaiable. For
instance, a public party may not `hide` a secret but it may `verify`
proof and `check` that a given call yields a certain value in a given
proof.

Commands are `apply`, `call`, `check`, `disclose`, `disclosed`,
    `env`, `exit`, `hide`, `prove`, `prover`, `public`, `verify`, and
    `verifier`.
    
Run it simply as `./zsim.py`.
