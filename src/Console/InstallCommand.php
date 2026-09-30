<?php

declare(strict_types=1);

namespace Loongs\OAuth\Console;

use Loongs\Support\Env;
use Loongs\OAuth\Storage\OrmStorage;
use Loongs\Orm\Orm;
use Loongs\Support\BasePath;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * ./loongs oauth:install [connection] [--prefix=] [--tables=oauth_] [--engine=] [--charset=] [--collation=] [--dry-run]
 *
 * Creates the OAuth tables (CREATE TABLE IF NOT EXISTS) in a database: a connection name from
 * config/database.php (default: the default connection) or a mysql:// URL. Table prefix / engine /
 * charset / collation come from that connection's config unless given as options.
 * Register in server/config/console.php: 'commands' => [\Loongs\OAuth\Console\InstallCommand::class].
 */
#[AsCommand(name: 'oauth:install', description: 'Create the loongs/oauth tables in a database (idempotent)')]
final class InstallCommand extends Command
{
    protected function configure(): void
    {
        $this->addArgument('connection', InputArgument::OPTIONAL, 'Connection name (config/database.php) or mysql:// URL; default = default connection')
            ->addOption('prefix', null, InputOption::VALUE_REQUIRED, 'Connection table prefix (default: the connection config "prefix")')
            ->addOption('tables', null, InputOption::VALUE_REQUIRED, 'Base prefix of the OAuth tables', OrmStorage::TABLES)
            ->addOption('engine', null, InputOption::VALUE_REQUIRED, 'Storage engine (default: config "engine", else InnoDB)')
            ->addOption('charset', null, InputOption::VALUE_REQUIRED, 'Charset (default: config "charset", else utf8mb4)')
            ->addOption('collation', null, InputOption::VALUE_REQUIRED, 'Collation (default: config "collation", else <charset>_bin)')
            ->addOption('dry-run', null, InputOption::VALUE_NONE, 'Print the DDL without connecting');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $base = class_exists(BasePath::class) ? BasePath::get() : (string) getcwd();
        if (class_exists(Env::class) && is_file($base . '/.env')) {
            Env::load($base . '/.env');
        }
        $file = $base . '/config/database.php';
        $db = is_file($file) ? (static fn (): mixed => require $file)() : [];
        $db = is_array($db) ? $db : [];
        Orm::configure($db);

        $name = $input->getArgument('connection');
        $name = is_string($name) && $name !== '' ? $name : (string) ($db['default'] ?? 'mysql');
        $raw = [];
        if (!str_contains($name, '://')) {
            $raw = $db['connections'][$name] ?? null;
            if (!is_array($raw)) {
                $io->error("Database connection [{$name}] is not configured in config/database.php.");

                return Command::FAILURE;
            }
        }
        $opt = static fn (string $k): ?string => is_string($v = $input->getOption($k)) && $v !== '' ? $v : (isset($raw[$k]) && is_scalar($raw[$k]) && $raw[$k] !== '' ? (string) $raw[$k] : null);
        try {
            $storage = new OrmStorage($name, $opt('prefix') ?? (str_contains($name, '://') ? null : ''), (string) $input->getOption('tables'),
                $opt('engine'), $opt('charset'), $opt('collation'));
            if ($input->getOption('dry-run')) {
                foreach ($storage->schema() as $ddl) {
                    $output->writeln($ddl . ";\n");
                }

                return Command::SUCCESS;
            }
            $target = Orm::resolver()->spec($name)->describe();
            $rows = [];
            foreach ($storage->install() as $table => $created) {
                $rows[] = [$table, $created ? 'created' : 'exists'];
            }
        } catch (\Throwable $e) {
            $io->error($e->getMessage());

            return Command::FAILURE;
        }
        $io->writeln("oauth:install on {$target}");
        $io->table(['table', 'status'], $rows);
        $io->success('OAuth tables ready (' . count($rows) . ').');

        return Command::SUCCESS;
    }
}
