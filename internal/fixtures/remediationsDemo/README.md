# Datree Remeediations PoC

## have a rule you need to fix? no worries just remediate it

[![Build Status](https://travis-ci.org/joemccann/dillinger.svg?branch=master)](https://travis-ci.org/joemccann/dillinger)

## Usage

in this feature demo we will go through

1. how to run a remediations on a failed rule
2. create your own remedations config

### pre-requirments

```sh
$ cd <cli-service> && git checkout FEAT_remediations && npm run start:dev;
$ cd <datree-cli> && git checkout remediate_command_wip
```

### the problem we're trying to solve

```sh
$ ./datree test ./internal/fixtures/remediationsDemo/fix-me.yaml
```

![Screen Shot 2022-08-30 at 10 09 19](https://user-images.githubusercontent.com/51760613/187386371-64d76ed5-4067-4906-a26b-67dd0de93f2e.png)

see that failed error? you need to fix it now, but your not sure how or whats the best practice
don't worry `./datree remediate run` is here to the rescue.
Datree will create a patch file for each k8 resource so you can patch it directly to your cluster

### solution

```sh
$ ./datree remediate run ./internal/fixtures/remediationsDemo/fix-me.yaml
```

notice that datree created a **patches** directory where all the patches live.
![Screen Shot 2022-08-30 at 10 18 39](https://user-images.githubusercontent.com/51760613/187386444-eddee836-0dfe-4687-a55f-048471fe5b21.png)

patch your cluster using `kubectl`

```sh
$ kubectl patch deployment rss-site --type json --patch-file patches/Deployment-rss-site-fixed.yml
```

## Custom Remediations

notice an example remediations config file is under `./internal/fixtures/remediationsDemo/remediate-example.json`
it is built as

```json
{
  "[rule identifier]": {
    "remediate": "{JsonPatch}"
  }
}
```

### publish

```sh
$ ./datree remediate publish ./internal/fixtures/remediationsDemo/remediate-example.json
```

now everytime youll run remediate youll use your published config file, go on change the file give it a try!

## Unknowns

- how to save the user remediation config file (db | raw)
- should use namespace to differ resource in case of multiple files with the same name and kind
- how should we behave in when there are no failed rules (prompt success message?)
- how should we behave in when there is a yaml error/ k8s config error
- should we use multiple fixes for 1 rule
- should we add fix metadata (like in https://kyverno.io/docs/writing-policies/mutate/ [match | api version | etc])
- should we create a fix specifically for helm | kustomize
- should we create a default remediation config file for all our rules (create a generic fix for each rule)?
- should we use a yaml file for a custom remediations config
  MIT

**Free Software, Hell Yeah!**
