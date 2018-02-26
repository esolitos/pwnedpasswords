# `esolitos/pwnedpasswords`: Check how broken is your password

Generic php service built to query Troy Hunt's https://pwnedpasswords.com API service and let you know how "broken" is your password, *without actually sending your password*.

More info about this on Troy's [first blog post](https://www.troyhunt.com/introducing-306-million-freely-downloadable-pwned-passwords/) _(about Pwned Passwords v1)_, the [follow up post](https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/) _(about v2, the version used by this library)_ and finally [the post on Cloudflare](https://blog.cloudflare.com/validating-leaked-passwords-with-k-anonymity/) blog _(in which k-anonymity is explained in depth)_.

## Installation

Via composer: `composer require esolitos/pwnedpasswords`

## Usage

The usage is very simple, just create the object and call

```php
$mySafePassword = 'p@ssword';

$validator = Esolitos\PwnedPasswords\PwnageValidator();
$pwnedCount = $validator->getPasswordPwnage($mySafePassword);

print_r($pwnedCount)

> 47205

```


### _Bonus points: Drupal module_

This library was initially built for the drupal module: [Pwned Passwords](https://www.drupal.org/project/pwned_passwords)
