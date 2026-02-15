import { app } from './app';

const defaultPort = 3004; // Standardize on 3004 for Liquor Store Demo
const rawPort = process.env.PORT || process.env.VERIFIER_PORT;
const parsedPort = rawPort ? Number.parseInt(rawPort, 10) : defaultPort;
const port = Number.isFinite(parsedPort) ? parsedPort : defaultPort;

app.listen(port, () => {
    console.log(`mitch Pilot Verifier listening at http://localhost:${port}`);
    console.log('Waiting for Wallet presentations on /present');
});
