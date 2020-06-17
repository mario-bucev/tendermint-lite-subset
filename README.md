# Prusti on Tendermint.rs lite module
Code extracted from the [Tendermint.rs](https://github.com/informalsystems/tendermint-rs/tree/master/tendermint/src/lite) lite module with some adaptations.

# Running
Clone \& build [the branch for first support of arrays and slice](https://github.com/mario-bucev/prusti-dev/tree/arrays-repeat). Note: building \& using the `release` build is recommended.

Navigate to the `src` folder and run Prusti with `RUST_LOG=error prusti main.rs`.

After ~3mins, it should report one or two errors. If we run Silicon on the dumped Viper program, we get to know the errors more precisely:
```
  [0] Exhale might fail. There might be insufficient permission to access slice$u8(_old$pre$1). (program.vpr@5094.3)
  [1] Assignment might fail. There might be insufficient permission to access _50.val_int. (program.vpr@10446.3)
```
The first one is due to our imperfect code generation. We think the second one is due to an [issue in Silicon](https://github.com/viperproject/silicon/issues/481), as the assignment:
```
_50 := builtin$havoc_ref()
inhale acc(_50.val_int, write)
// Assignment might fail. 
// There might be insufficient permission 
// to access _50.val_int
_50.val_int := _3.val_int
```
should not fail since we `inhaled` the permission in the previous statement.

# Packages versions
* `viper` 0.1-202006120938
* `viper-viper.silicon` 1.1-202006120938
* `viper-viper.carbon` 1.0-202006120938
* `viper-z3` 4.4.0-202005140149
* `viper-boogie` 2015.06.10-202006120938