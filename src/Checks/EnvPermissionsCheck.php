<?php

namespace BluedotBd\SanityCheck\Checks;

use BluedotBd\SanityCheck\Results\Result;

class EnvPermissionsCheck extends Check
{
    public function key(): string
    {
        return 'env_permissions';
    }

    public function label(): string
    {
        return 'File permissions';
    }

    public function run(): Result
    {
        if (DIRECTORY_SEPARATOR !== '/') {
            return $this->pass('Not applicable on Windows.');
        }

        $path = base_path('.env');

        if (! is_file($path)) {
            return $this->warn('No .env file found in the application root.');
        }

        $permissions = fileperms($path) & 0777;

        if ($permissions & 0004) {
            return $this->warn(sprintf('.env is world-readable (%04o) - chmod 600 it.', $permissions));
        }

        return $this->pass(sprintf('.env permissions are %04o.', $permissions));
    }
}