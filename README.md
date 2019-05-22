# npm-audit-amalgamate

The purpose of this project is to amalgamate several npm audit json files

npm audit json files can be created using the following syntax

```bash
npm audit --json > my-audit.json
```

The amalgamate.py script takes three arguments:

- output, The file to output the amalgamated audit data to.  
- type, The type of dependencies to report audit details on.  This argument can be devDependencies, dependencies or both.    
- inputs, The input json audit files.  

## Example arguments

```bash
python3 amalgamate.py output.txt both sample-data/handlebars.json,sample-data/browser-sync.json
```

## Sample Output

```text
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│Project                       │ Critical  High      Moderate  Low       Info                        │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│browser-sync                  │ 0         1         0         0         0                           │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│High           │ Code Injection                                                                     │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Package        │ crossbow                                                                           │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Dependency of  │ crossbow                                                                           │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Path           │ crossbow > js-yaml                                                                 │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│More info      │ https://npmjs.com/advisories/813                                                   │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Project        │ sample-data/browser-sync.json                                                      │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘

```

  

