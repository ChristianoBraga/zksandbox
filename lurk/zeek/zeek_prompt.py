try:
    import os
    import json
    import prompt_toolkit as pt
    from lurk_wrapper import *
    from zeek_env import *
except Exception as e:
    print(e)
    print('Check your Python 3 installation.')
    print('Either json, prompt_toolkit, lurk_wrapper or zeek_env is missing.')
    exit(1) 

class ZeekPrompt:
    def __init__(self, path):
        self._zeek_env = ZeekEnv(path)
        self.completer = pt.completion.WordCompleter(
            ['call', 'check', 'disclose', 'disclosed', 'env', 'exit', 'help',
             'hide', 'party', 'prove', 'public', 'verify'], ignore_case=True)
        self.session = pt.PromptSession(history=pt.history.FileHistory(self._zeek_env.get_hist()))
        labels_file_name = f'{path}/labels.json' 
        if os.path.exists(labels_file_name) and \
           os.path.getsize(labels_file_name) > 0:
            fh = open(labels_file_name, 'r')
            self._labels = json.load(fh)
            fh.close()
        else:
            self._labels = {}

    def good_bye(self):
        print('\nBye')
        if self._labels != {}:
            labels_file_name = f'{self._zeek_env.get_path()}/labels.json'
            fh = open(labels_file_name, 'w')
            json.dump(self._labels, fh, indent=4)  
            fh.close()              

    def _right_prompt(self, party):
        if party != None and ZeekEnv.is_hash(party):
            if not self.empty_labels():
                k = [l for l, v in self._labels.items() if v == party]
                return f'{k[0]}:{party[:4]}...{party[len(party) - 4:]}'
            else:
                return f'{party[:4]}...{party[len(party) - 4:]}'
        elif party == 'public':
            return 'public'
        else:
            return ''

    def prompt(self):
        # return self.session.prompt('zeek ❯ ', completer=self.completer, rprompt=party)
        return self.session.prompt('zeek ❯ ', rprompt=self._right_prompt(self._zeek_env.get_party()))

    def empty_labels(self):
        return self._labels == {}
    
    def get_labels(self):
        return self._labels.keys()

    def get_values(self):
        return self._labels.values()

    def get_items(self):
        return self._labels.items()
    
    def get_value(self, l):
        return self._labels[l]

    def set_label(self, l, v):
        self._labels[l] = v

    def is_public(self):
        return self._zeek_env.get_party() == 'public'
        
    def get_party(self):
        return self._zeek_env.get_party()

    def handle(self, cmd, args):
        match cmd:
            case 'call':
                self.handle_call(args[0], args[1])
            case 'hide':
                print('Type hide <value> in label <label> instead.')
            case 'check':
                proof_key = args[0]
                test      = args[1]
                value     = args[2]
                output    = args[3]
                self.handle_inspect(proof_key,test, value, output)

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
            parties.sort()
            [print(p) for p in parties]
        else:
            print('There are no parties')

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
                return None
            else:
                self._zeek_env.add_party(out)            
                value_str = ' '.join(value)    
                print(f'Party {out} created for {value_str}.')
                return out
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
               return None
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
                print(c)
        proofs = self._zeek_env.get_proofs_from_party()
        if proofs != []:
            print(f'Proofs from {party}:')
            for p in proofs:
                print(p)
                
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
