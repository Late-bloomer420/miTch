import { expect, it } from 'vitest';
import request from 'supertest';
import { app } from '../app';

it('rate-limits presentation attempts even when the caller rotates session IDs', async () => {
  for (let attempt = 0; attempt < 30; attempt++) {
    await request(app)
      .post('/oid4vp-present')
      .set('X-AskMI-Session-Id', `rate-limit-${attempt}`)
      .send({})
      .expect(400);
  }
  const limited = await request(app)
    .post('/oid4vp-present')
    .set('X-AskMI-Session-Id', 'rate-limit-new-session')
    .send({})
    .expect(429);
  expect(Number(limited.headers['retry-after'])).toBeGreaterThan(0);

  // Presentation throttling must not prevent the UI from reading its state.
  await request(app).get('/status').set('X-AskMI-Session-Id', 'rate-limit-new-session').expect(200);
});
