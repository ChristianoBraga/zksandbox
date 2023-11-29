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
        '''
        A call executes the application of test to value.
        Both commits should be desclosed to the current party, either
        because they were hidden by the current party itself or they were
        sent from another party to the current party.
        '''
        assert(type(value) != list)
        if self._zeek_env.get_party() == None:
            print('Run command party first to set current party.')
            return
        if not self._zeek_env.is_commited_by_current_party(test):
            print(f'Secret {test} was not hiden nor sent to {self._zeek_env.get_party()}.')
            return
        if not self._zeek_env.is_commited_by_current_party(value):
            print(f'Secret {value} was not hiden nor sent to {self._zeek_env.get_party()}.')
            return            
        try:
            cd, pd = self._zeek_env.get_current_party_dirs()
            lurkw = LurkWrapper(self._zeek_env.get_timeout(), cd, pd)
            out = lurkw.call('0x'+test, '0x'+value)
            print(out)
        except Exception as e:
            print(e)
            print(f'Unexpected error while executing Call.')

    def handle_hide(self, value):
        assert(type(value) == list)
        try:
            cd, pd = self._zeek_env.get_current_party_dirs()
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
    
    def handle_parties(self):
        parties = self._zeek_env.get_parties()
        if parties != []:
            print('Parties:')
            parties.sort()
            [print(f'\t{p}') for p in parties]

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
        try:
            cd, pd = self._zeek_env.get_current_party_dirs()
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

    def handle_prove(self, test, value):
        try:
            cd, pd = self._zeek_env.get_current_party_dirs()
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

    def handle_verify(self, proof_key):
        try:
            cd, pd = self._zeek_env.get_current_party_dirs()
            lurkw = LurkWrapper(self._zeek_env.get_timeout(), cd, pd)
            out = lurkw.verify(proof_key)
            print(out)
        except Exception as e:
            print(e)
            print(f'Unexpected error while executing Verify.')

    def handle_inspect(self, proof_key, test, value, output):
        try:
            cd, pd = self._zeek_env.get_current_party_dirs()
            lurkw = LurkWrapper(self._zeek_env.get_timeout(), cd, pd)
            rc, out = lurkw.inspect(f'\"{proof_key}\"', f'0x{test}', f'0x{value}', output)       
            print(out)
            if rc > 0:
                print('Inspect failed.')
        except Exception as e:
            print(e)
            print(f'Unexpected error while executing Inspect.')

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
                
    def handle_send_commit(self, target_party, hash):
        if self._zeek_env.is_commited_by_current_party(hash): 
            self._zeek_env.send_commit_from_current_party(target_party, hash)
            print(f'Secret {hash} sent to {target_party}.')
        else:
            print(f'Secret {hash} was not commited by {self._zeek_env.get_party()}.')

    def handle_send_proof(self, target_party, proof):
        if self._zeek_env.is_proven_by_current_party(proof): 
            self._zeek_env.send_proof_from_current_party(target_party, proof)
            print(f'Proof {proof} sent to {target_party}.')
        else:
            print(f'Proof {proof} was not generated by {self._zeek_env.get_party()}.')
