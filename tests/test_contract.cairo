use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use starknet::ContractAddress;


#[test]
fn test_increase_balance() {}

#[test]
#[feature("safe_dispatcher")]
fn test_cannot_increase_balance_with_zero_value() {}
