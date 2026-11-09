<?php

declare(strict_types=1);

namespace Loongs\OAuth\Console;

use Loongs\OAuth\Jwt\EncryptionKey;
use Loongs\OAuth\Jwt\SigningKey;
use Loongs\OAuth\Support\Keys;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * ./loongs oauth:keygen <jwt|sk|token|refresh_token> [--alg=ES256] [--encryption] [--out=dir]
 *
 * Prints CSPRNG key / token material once. jwt → SigningKey PEM (+ optional EncryptionKey PEM);
 * sk / token / refresh_token → opaque strings (sk_… / short access / long refresh).
 * Register in server/config/console.php: 'commands' => [\Loongs\OAuth\Console\KeygenCommand::class].
 */
#[AsCommand(name: 'oauth:keygen', description: 'Generate loongs/oauth key or token material (jwt | sk | token | refresh_token)')]
final class KeygenCommand extends Command
{
    protected function configure(): void
    {
        $this->addArgument('type', InputArgument::REQUIRED, 'jwt | sk | token | refresh_token')
            ->addOption('alg', null, InputOption::VALUE_REQUIRED, 'JWT signing algorithm (RS256 | ES256)', 'ES256')
            ->addOption('encryption', null, InputOption::VALUE_NONE, 'With jwt: also mint an RSA-OAEP-256 EncryptionKey PEM')
            ->addOption('encryption-dir', null, InputOption::VALUE_NONE, 'With jwt: also mint a dir (32-byte) EncryptionKey instead of RSA')
            ->addOption('out', null, InputOption::VALUE_REQUIRED, 'Directory to write PEM files (jwt only); default = stdout');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $type = (string) $input->getArgument('type');
        if (!in_array($type, Keys::TYPES, true)) {
            $io->error("Unknown type [{$type}] (jwt | sk | token | refresh_token).");

            return Command::FAILURE;
        }

        try {
            return match ($type) {
                Keys::JWT => $this->emitJwt($input, $io),
                Keys::SK, Keys::TOKEN, Keys::REFRESH_TOKEN => $this->emitOpaque($type, $io),
            };
        } catch (\Throwable $e) {
            $io->error($e->getMessage());

            return Command::FAILURE;
        }
    }

    private function emitOpaque(string $type, SymfonyStyle $io): int
    {
        $value = Keys::generate($type);
        $label = match ($type) {
            Keys::SK => 'sk (client / API secret — show once; store Crypto::hashSecret only)',
            Keys::TOKEN => 'token (short access-token material — store Crypto::hashToken)',
            Keys::REFRESH_TOKEN => 'refresh_token (long refresh-token material — store Crypto::hashToken)',
            default => $type,
        };
        $io->writeln("<info>{$label}</info>");
        $io->writeln((string) $value);
        $io->warning('This value is shown once. Do not commit it or write it to logs.');

        return Command::SUCCESS;
    }

    private function emitJwt(InputInterface $input, SymfonyStyle $io): int
    {
        $alg = (string) $input->getOption('alg');
        /** @var SigningKey $signing */
        $signing = Keys::jwt($alg);
        $out = $input->getOption('out');
        $wantEnc = (bool) $input->getOption('encryption') || (bool) $input->getOption('encryption-dir');

        if (is_string($out) && $out !== '') {
            if (!is_dir($out) && !mkdir($out, 0700, true) && !is_dir($out)) {
                throw new \RuntimeException("Cannot create output directory [{$out}].");
            }
            $sigPath = rtrim($out, '/\\') . DIRECTORY_SEPARATOR . 'oauth-signing-' . $signing->kid . '.pem';
            if (file_put_contents($sigPath, $signing->toPem()) === false) {
                throw new \RuntimeException("Failed to write {$sigPath}");
            }
            @chmod($sigPath, 0600);
            $io->writeln("signing ({$signing->alg}, kid={$signing->kid}): {$sigPath}");
            if ($wantEnc) {
                $enc = $input->getOption('encryption-dir')
                    ? EncryptionKey::generateDirect()
                    : EncryptionKey::generateRsa();
                if ($enc->alg === EncryptionKey::DIR) {
                    $encPath = rtrim($out, '/\\') . DIRECTORY_SEPARATOR . 'oauth-encryption-' . $enc->kid . '.bin';
                    if (file_put_contents($encPath, (string) $enc->secret()) === false) {
                        throw new \RuntimeException("Failed to write {$encPath}");
                    }
                } else {
                    $encPath = rtrim($out, '/\\') . DIRECTORY_SEPARATOR . 'oauth-encryption-' . $enc->kid . '.pem';
                    if (file_put_contents($encPath, (string) $enc->privatePem()) === false) {
                        throw new \RuntimeException("Failed to write {$encPath}");
                    }
                }
                @chmod($encPath, 0600);
                $io->writeln("encryption ({$enc->alg}, kid={$enc->kid}): {$encPath}");
            }
            $io->warning('PEM / key files written with mode 0600 when supported. Keep them out of git.');

            return Command::SUCCESS;
        }

        $io->writeln("<info>jwt signing ({$signing->alg}, kid={$signing->kid})</info>");
        $io->writeln($signing->toPem());
        if ($wantEnc) {
            $enc = $input->getOption('encryption-dir')
                ? EncryptionKey::generateDirect()
                : EncryptionKey::generateRsa();
            if ($enc->alg === EncryptionKey::DIR) {
                $io->writeln("<info>jwt encryption (dir, kid={$enc->kid}) — 32 raw bytes, base64url:</info>");
                $io->writeln(\Loongs\OAuth\Support\Crypto::base64UrlEncode((string) $enc->secret()));
            } else {
                $io->writeln("<info>jwt encryption ({$enc->alg}, kid={$enc->kid})</info>");
                $io->writeln((string) $enc->privatePem());
            }
        }
        $io->warning('Private key material is shown once. Do not commit it or write it to logs.');

        return Command::SUCCESS;
    }
}