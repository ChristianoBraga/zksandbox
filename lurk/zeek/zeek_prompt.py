try:
    import prompt_toolkit as pt
    from lurk_wrapper import *
    from zeek_env import *
except Exception as e:
    print(e)
    print('Check your Python 3 installation.')
    print('Either prompt_toolkit, lurk_wrapper or zeek_env is missing.')
    exit(1) 

class ZeekPrompt:
    def __init__(self, zeek_env):
        self._zeek_env = zeek_env
        self.completer = pt.completion.WordCompleter(
            ['call', 'check', 'disclose', 'disclosed', 'env', 'exit', 'help',
             'hide', 'party', 'prove', 'public', 'verify'], ignore_case=True)
        self.session = pt.PromptSession(history=pt.history.FileHistory(zeek_env.get_hist()))

    def prompt(self):
        # return self.session.prompt('zeek ❯ ', completer=self.completer, rprompt=party)
        return self.session.prompt('zeek ❯ ', rprompt=self._zeek_env.get_party())

    def handle_call(self, test, value):
        assert(type(value) != list)
        try:
            cd, pd = self._zeek_env.get_dirs()
            lurkw = LurkWrapper(self._zeek_env.get_timeout(), cd, pd)
            out = lurkw.call('0x'+test, '0x'+value)
            print(out)
        except Exception as e:
            print(e)
            print(f'Unexpected error while executing Call.')

    def handle_hide(self, value):
        assert(type(value) == list)
        if not self._zeek_env.is_public():
            try:
                cd, pd = self._zeek_env.get_dirs()
                lurkw = LurkWrapper(self._zeek_env.get_timeout(), cd, pd)
                rc, out = lurkw.hide(value)
                if rc > 0:
                    print(out)
                    print('Hide failed.')
                    return None
                else:
                    value_str = ' '.join(value)
                    print(f'Value {value_str} hidden as {out}')
                    return out
            except Exception as e:
                print(e)
                print('Unexpected error while executing hide.')
        else:
            print('Public can\'t hide.')
            return None

    def handle_parties(self):
        parties = self._zeek_env.get_parties()
        if parties != []:
            print('Parties:')
            parties.sort()
            [print(p) for p in parties]

    def handle_party(self, hash):
        current_party = self._zeek_env.get_party()  
        if hash == current_party:
            print(f'Party is already {current_party}.')
        else: 
            if self._zeek_env.set_party(hash):
                print(f'Party set to {hash}.')
            else:
                print(f'Party {hash} does not exist.\nParty is still {self._zeek_env.get_party()}.')
                print('Party failed.')


    def handle_new_party(self, value):
        assert(type(value) == list)
        if self._zeek_env.is_public():
            try:
                cd, pd = self._zeek_env.get_dirs()
                lurkw = LurkWrapper(self._zeek_env.get_timeout(), cd, pd)
                rc, out = lurkw.hide(value)
                if rc > 0:
                    print(out)
                    print('New party failed.')
                else:
                    self._zeek_env.add_party(out)            
                    value_str = ' '.join(value)    
                    print(f'Party {out} created for {value_str}.')
            except Exception as e:
                print(e)
                print('Unexpected error while executing New party.')
        else:
            print('Only Public can Party.')

    def handle_prove(self, test, value):
        if not self._zeek_env.is_public():
            try:
                cd, pd = self._zeek_env.get_dirs()
                lurkw = LurkWrapper(self._zeek_env.get_timeout(), cd, pd)
                rc, out = lurkw.prove('0x'+test, '0x'+value)
                key = None
                if rc > 0:
                    print(out)
                    print('Prove failed.')
                else:
                    key = out
                    print(f'Proof key {out} generated for call {test} {value}')
                return key
            except Exception as e:
                print(e)
                print(f'Unexpected error while executing Prove.')
        else:
            print('Public can\'t prove.')

    def handle_verify(self, proof_key):
        try:
            cd, pd = self._zeek_env.get_dirs()
            lurkw = LurkWrapper(self._zeek_env.get_timeout(), cd, pd)
            out = lurkw.verify(proof_key)
            print(out)
        except Exception as e:
            print(e)
            print(f'Unexpected error while executing Verify.')

    def handle_inspect(self, proof_key, test, value, output):
        try:
            cd, pd = self._zeek_env.get_dirs()
            lurkw = LurkWrapper(self._zeek_env.get_timeout(), cd, pd)
            rc, out = lurkw.inspect('\"'+proof_key+'\"', '0x'+test, '0x'+value, output)       
            print(out)
            if rc > 0:
                print('Inspect failed.')
        except Exception as e:
            print(e)
            print(f'Unexpected error while executing Inspect.')

    def handle_disclose_proof(self, proof):
        if not self._zeek_env.is_public():
            if proof != None:
                if ZeekEnv.is_proof(proof):
                    self._zeek_env.disclose_proof_from_party(proof)
                    print(f'Proof {proof} disclosed.')
                else:
                    print(f'Proof {proof} in wrong format.')
            else:
                print(f'Can\'t disclose {proof}.')
        else:       
            print('Public can\'t disclose.')

    def handle_disclose_hash(self, hash):
        if not self._zeek_env.is_public():
            if hash != None:
                self._zeek_env.disclose_commit_from_party(hash)
                print(f'Hash {hash} disclosed.')
            else:
                print(f'Can\'t disclose {hash}.')
        else:
            print('Public can\'t disclose.')

    def handle_disclose(self, last_secret, last_proof):
        if not self._zeek_env.is_public():
            if last_secret != None:
                self._zeek_env.disclose_commit_from_party(last_secret)
                print(f'Hash {last_secret} disclosed.')
            elif last_proof != None:
                self._zeek_env.disclose_proof_from_party(last_proof)
                print(f'Proof key {last_proof} disclosed.')
            else:
                print('Nothing to disclose.')
        else:
            print('Public can\'t disclose.')
        return None, None

    def handle_disclosed(self):
        print(f'Commits from public:')
        for c in self._zeek_env.get_commits('public'):
            print(c)
        print(f'Proofs from public:')
        for p in self._zeek_env.get_proofs('public'):
            print(p)

    def handle_env(self):
        party = self._zeek_env.get_party()
        commits = self._zeek_env.get_commits_from_party()
        if commits != []:
            print(f'Commits from {party}:')
            for c in commits:
                print(f'\t{c}')
        proofs = self._zeek_env.get_proofs_from_party()
        if proofs != []:
            print(f'Proofs from {party}:')
            for p in proofs:
                print(f'\t{p}')
