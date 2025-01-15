import express, { Request, Response } from 'express';
import { z } from 'zod';
import cors from 'cors';
import { verifySignInMessage, createAppClient, viemConnector } from '@farcaster/auth-client';
import jwt from 'jsonwebtoken';
import { insertToken, getToken } from './database.js';
import { createPublicClient, http, getContract } from 'viem';
import { base } from 'viem/chains';
import fs from 'fs';

const debug = process.env.DEBUG === 'true';

const LoginSchema = z.object({
    fid: z.number().int().positive(),
    username: z.string(),
    signature: z.string(),
    nonce: z.string(),
    message: z.string(),
    domain: z.string()
});

type LoginPayload = z.infer<typeof LoginSchema>;

interface ResponseBody {
    success: boolean;
    message: string;
    payload?: any;
}

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());
app.use(cors());

const appClient = createAppClient({
    relay: 'https://relay.farcaster.xyz',
    ethereum: viemConnector()
});

// Define the RPC URL for the Base blockchain
const baseRpcUrl = process.env.BASE_RPC_URL as string;

// Create a public client for the Base blockchain
const baseClient = createPublicClient({
  chain: base,
  transport: http(baseRpcUrl),
});

// Read the ABI from the file specified in the environment variable
const hackathonAbiFilePath = process.env.HACKATHON_CONTRACT_ABI as string;
const hackathonContractAbi = JSON.parse(fs.readFileSync(hackathonAbiFilePath, 'utf-8'));

// Get the contract address from environment variables
const hackathonContractAddress = process.env.HACKATHON_CONTRACT_ADDRESS as `0x${string}`;

const hackathonToken = await baseClient.readContract({
    address: hackathonContractAddress,
    abi: hackathonContractAbi,
    functionName: 'HACKATHON_TOKEN',
} as any) as `0x${string}`;

const minTokenRequirement = await baseClient.readContract({
    address: hackathonContractAddress,
    abi: hackathonContractAbi,
    functionName: 'MIN_TOKEN_REQUIREMENT',
} as any) as bigint;

const clankerTokenAbiFilePath = process.env.CLANKER_TOKEN_ABI as string;
const clankerTokenAbi = JSON.parse(fs.readFileSync(clankerTokenAbiFilePath, 'utf-8'));

const getHackathonTokenBalance = async (addresses: Set<`0x${string}`>) => {
    const addressArray = Array.from(addresses);

    const balancePromises = addressArray.map(address => baseClient.readContract({
        address: hackathonToken,
        abi: clankerTokenAbi,
        functionName: 'balanceOf',
        args: [address]
    }));

    const balances = await Promise.all(balancePromises) as bigint[];
    console.log("Balances for user:", balances);
    const sum = balances.reduce((acc, curr) => acc + curr, 0n);
    return sum;
}

const hasEnoughHackathonTokens = async (addresses: Set<`0x${string}`>) => {
    const balance = await getHackathonTokenBalance(addresses);
    const hasEnough = balance >= minTokenRequirement;
    console.log("Has enough tokens?", hasEnough, addresses);
    return hasEnough;
}

console.log("Minimum token requirement:", minTokenRequirement);

app.post('/api/webhook', async (req: Request, res: Response) => {
    console.log("Webhook request:", req.body);
    return res.status(200).json({
        success: true,
        message: 'Webhook received'
    } as ResponseBody);
});

app.post('/api/revalidate', async (req: Request, res: Response) => {
    console.log("Revalidate request:", req.body);
    const jwt = req.body?.jwt;

    if (typeof jwt !== 'string') {
        console.log('Invalid POST body, rejecting', typeof jwt);
        return res.status(400).json({
            success: false,
            message: 'Invalid jwt'
        } as ResponseBody);
    }

    const token = getToken(jwt);

    const now = Math.floor(Date.now() / 1000);

    const expired = token ? (token.expires_at < now ? "yes" : "no") : "unset";

    console.log(`Revalidate: exists? ${!!token}, expired? ${expired}`);

    if (!token || token.expires_at < Math.floor(Date.now() / 1000)) {
        return res.status(400).json({
            success: false,
            message: 'Token invalid'
        } as ResponseBody);
    }
    
    return res.status(200).json({
        success: true,
        message: 'Token valid',
        payload: token
    } as ResponseBody);
});

app.post('/api/login', async (req: Request, res: Response) => {
    try {
        const result = LoginSchema.safeParse(req.body);

        if (!result.success) {
            return res.status(400).json({
                success: false,
                message: 'Invalid payload'
            } as ResponseBody);
        }

        const { fid, signature, message, nonce, domain, username } = (result.data as LoginPayload);

        try {
            const { success, fid: challengeFid } = await verifySignInMessage(appClient, {
                nonce,
                message,
                signature: signature as `0x${string}`,
                domain,
            });

            console.log("success?", success, fid);

            if (!success || fid !== challengeFid) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid signature or FID mismatch'
                } as ResponseBody);
            }

            const { pfp, addresses, powerBadge, addresses: ethAddresses } = await getUserByFid(fid);

            const hasEnoughTokens = await hasEnoughHackathonTokens(ethAddresses);

            if (!hasEnoughTokens) {
                console.log("User does not have enough tokens");

                if (debug) {
                    console.debug("Debug mode enabled, skipping token requirement");
                }
                else {
                    return res.status(401).json({
                        success: false,
                        message: 'Insufficient tokens'
                    } as ResponseBody);
                }
            }

            const cleansedUsername = username.toLowerCase().replace('.', '_').replace(/[^a-z0-9_-]/g, '');

            const jwt = generateGetStreamJWT(cleansedUsername);

            insertToken(jwt, Math.floor(Date.now() / 1000) + 24 * 60 * 60, false, fid);

            // At this point, the signature is valid and the FID matches and they have enough tokens
            return res.status(200).json({
                success: true,
                message: 'Login successful',
                payload: {
                    username: cleansedUsername,
                    farcasterUsername: username,
                    jwt,
                    pfp,
                    addresses,
                    powerBadge
                }
            } as ResponseBody);

        } catch (verifyError) {
            console.error('Signature verification error:', verifyError);
            return res.status(401).json({
                success: false,
                message: 'Signature verification failed'
            } as ResponseBody);
        }

    } catch (error) {
        console.error('Login error:', error);
        return res.status(500).json({
            success: false,
            message: 'Internal server error'
        } as ResponseBody);
    }
});

function generateGetStreamJWT(userID: string): string {
    const secretKey = process.env.GETSTREAM_SECRET_KEY;
    if (!secretKey) {
        throw new Error('GETSTREAM_SECRET_KEY is not defined in environment variables');
    }

    const payload = {
        user_id: userID,
    };

    const options = {
        expiresIn: '24h',
    };

    return jwt.sign(payload, secretKey, options);
}

async function getUserByFid(fid: number) {
    const url = `https://api.neynar.com/v2/farcaster/user/bulk?fids=${fid}`;
    const options = {
        method: 'GET',
        headers: {
            accept: 'application/json',
            'x-neynar-experimental': 'false',
            'x-api-key': process.env.NEYNAR_API_KEY as string
        }
    };

    const response = await fetch(url, options);
    const data: Record<string, any> = await response.json();
    const user = data.users?.[0];

    if (!user) {
        throw new Error('User not found');
    }

    const username: string = user.username;
    const pfp: string = user.pfp_url;
    const addresses = new Set<`0x${string}`>([
        user.custody_address,
        ...user.verified_addresses.eth_addresses
    ]);
    const powerBadge: boolean = user.power_badge;

    return {
        fid,
        username,
        pfp,
        addresses,
        powerBadge
    };
}

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
}); 