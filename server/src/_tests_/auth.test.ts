import request from 'supertest';
import app from '../app'; // Adjust the path to your Express app
import { OAuth2Client, LoginTicket } from 'google-auth-library';
import { User } from '@models/User.model'; // Adjust the path to your User model
import { generateAccessTokenAndRefreshToken } from '@controllers/user.controller';

// Mock dependencies
jest.mock('google-auth-library'); // Mock Google OAuth2 client
jest.mock('../../models/User.model.ts'); // Mock the database model
// jest.mock('../../utils/tokenUtils'); // Mock token utility functions

describe('POST /api/v1/auth/google/callback', () => {
  let client: OAuth2Client;

  beforeEach(() => {
    client = new OAuth2Client() as jest.Mocked<OAuth2Client>; // Cast to Jest's mocked type
  });

  it('should return 200 and tokens on successful Google sign-in', async () => {
    const fakeUser = {
      _id: 'testUserId',
      email: 'test@example.com',
      name: 'Test User',
    };
    const idToken = 'valid-id-token';

    // Create a mock implementation for verifyIdToken that returns a valid LoginTicket
    const loginTicketMock: LoginTicket = {
      getPayload: jest.fn().mockReturnValue({
        iss: 'https://accounts.google.com',
        sub: '1234567890',
        aud: 'your-client-id',
        iat: 1643723900,
        exp: 1643727500,
        email: fakeUser.email,
        name: fakeUser.name,
      }),
      getEnvelope: jest.fn(), // Add mocked method
      getUserId: jest.fn().mockReturnValue(fakeUser._id), // Add mocked method
      getAttributes: jest.fn(), // Add mocked method
    } as unknown as LoginTicket; // Cast to unknown first

    // Mock the client.verifyIdToken method
    client.verifyIdToken = jest.fn().mockResolvedValue(loginTicketMock);

    // Mock user finding or creating
    (User.findOne as jest.Mock).mockResolvedValue(fakeUser);
    (User.create as jest.Mock).mockResolvedValue(fakeUser);

    // Mock token generation
    (generateAccessTokenAndRefreshToken as jest.Mock).mockResolvedValue({
      accessToken: 'test-access-token',
      refreshToken: 'test-refresh-token',
    });

    const res = await request(app)
      .post('/api/v1/auth/google/callback')
      .send({ idToken });

    expect(res.status).toBe(200);
    expect(res.body.data.accessToken).toBe('test-access-token');
    expect(res.body.data.refreshToken).toBe('test-refresh-token');
  });

  it('should return 400 on invalid ID token', async () => {
    const idToken = 'invalid-id-token';

    // Mock token verification failure
    client.verifyIdToken = jest
      .fn()
      .mockRejectedValue(new Error('Invalid token'));

    const res = await request(app)
      .post('/api/v1/auth/google/callback')
      .send({ idToken });

    expect(res.status).toBe(400);
    expect(res.body.message).toBe('Invalid ID token');
  });

  it('should return 500 if token generation fails', async () => {
    const idToken = 'valid-id-token';
    const fakeUser = {
      _id: 'testUserId',
      email: 'test@example.com',
      name: 'Test User',
    };

    // Create a mock implementation for verifyIdToken that returns a valid LoginTicket
    const loginTicketMock: LoginTicket = {
      getPayload: jest.fn().mockReturnValue({
        iss: 'https://accounts.google.com',
        sub: '1234567890',
        aud: 'your-client-id',
        iat: 1643723900,
        exp: 1643727500,
        email: fakeUser.email,
        name: fakeUser.name,
      }),
      getEnvelope: jest.fn(), // Add mocked method
      getUserId: jest.fn().mockReturnValue(fakeUser._id), // Add mocked method
      getAttributes: jest.fn(), // Add mocked method
    } as unknown as LoginTicket; // Cast to unknown first

    // Mock the client.verifyIdToken method
    client.verifyIdToken = jest.fn().mockResolvedValue(loginTicketMock);

    // Mock user lookup
    (User.findOne as jest.Mock).mockResolvedValue(fakeUser);

    // Mock token generation failure
    (generateAccessTokenAndRefreshToken as jest.Mock).mockRejectedValue(
      new Error('Token generation error')
    );

    const res = await request(app)
      .post('/api/v1/auth/google/callback')
      .send({ idToken });

    expect(res.status).toBe(500);
    expect(res.body.message).toBe('Failed to generate tokens');
  });
});
