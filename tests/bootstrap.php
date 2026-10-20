<?php

$autoloaders = [
    __DIR__ . '/../vendor/autoload.php',        // standalone package checkout
    __DIR__ . '/../../../vendor/autoload.php',  // monorepo: packages/sanity-check
];

foreach ($autoloaders as $autoload) {
    if (is_file($autoload)) {
        require $autoload;

        return;
    }
}

fwrite(STDERR, 'Run "composer install" first.' . PHP_EOL);

exit(1);