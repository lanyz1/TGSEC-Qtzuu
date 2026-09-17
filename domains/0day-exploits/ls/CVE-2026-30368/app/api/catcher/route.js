import crypto from 'crypto'

export async function POST(req) {
  try {
    const body = await req.json()

    const now = Math.floor(Date.now() / 1000)

    const payload = {
      Version: '3.8.3',
      DeviceID: crypto.randomUUID(),
      UserId: body.userId,
      EntitlementKey:
        body.cId === '61-6373-A000'
          ? '6b27a889-3a07d380-8637691b-742dcfb7-96650e0c-b1906f3d'
          : '5cc19a9d-c8e7bd90-3c7697f7-e3e6e85b-e9748236-e2174d17',
      Platform: 'catchon-extension',
      DeviceType: 'cros;x86_64;Google',
      ActivityList: [
        {
          Intervals: [
            { Start: now - 60, End: now - 30 }
          ],
          Timestamp: now - 30,
          Url: body.agentURL,
          Count: 1,
        }
      ],
      SentAt: Date.now(),
    }

    const res = await fetch(
      'https://agent.catchon.com/catcher/api/receive',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      }
    )

    const data = await res.json()

    return new Response(JSON.stringify(data), {
      status: res.status,
      headers: {
        'Content-Type': 'application/json',
      },
    })
  } catch (err) {
    console.error('[catcher route error]', err)
    return new Response(
      JSON.stringify({ error: 'Internal Server Error' }),
      { status: 500 }
    )
  }
}
