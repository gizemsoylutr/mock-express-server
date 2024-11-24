import express, { Request, Response, NextFunction } from "express";
import crypto from "crypto";
import { citizenInfo } from "./citizen-info";
import { API_KEY_VALUE, PORT_VALUE } from "./citizen.types";

const app = express();
const PORT = PORT_VALUE || 3000;

let API_KEY = API_KEY_VALUE || "default-key"; 
let lastGenerated = new Date(); 
let expiredKeys: Set<string> = new Set(); 

app.use(express.json());

app.get("/routes", (req, res) => {
    const routes: string[] = [];
    app._router.stack.forEach((middleware: { route: { path: string; }; }) => {
        if (middleware.route) {
            routes.push(middleware.route.path);
        }
    });
    res.json({ routes });
});

app.get("/current-api-key", (req: Request, res: Response) => {
    res.json({
        message: "Current API Key",
        apiKey: API_KEY, 
    });
});

const apiKeyMiddleware = (req: Request, res: Response, next: NextFunction) => {
    const clientApiKey = req.headers["x-api-key"];

    if (!clientApiKey || typeof clientApiKey !== "string") {
        res.status(403).json({ error: "Forbidden: API Key is missing" });
        return;
    }

    if (clientApiKey !== API_KEY) {
        if (expiredKeys.has(clientApiKey)) {
            res.status(403).json({ error: "Forbidden: API Key has expired" });
        } else {
            res.status(403).json({ error: "Forbidden: Invalid API Key" });
        }
        return;
    }

    next();
};

const tcknMiddleware = (req: Request, res: Response, next: NextFunction) => {
    const { tckn } = req.body;
    if (!tckn || typeof tckn !== "string" || tckn.length !== 11 || !/^\d+$/.test(tckn)) {
        res.status(400).json({ error: "Invalid or missing TCKN" });
        return;
    }
    next();
};

const generateApiKey = (): string => {
    return crypto.randomBytes(32).toString("hex"); 
};

const handleExpiredKey = (oldApiKey: string) => {
    expiredKeys.add(oldApiKey);

    setTimeout(() => {
        expiredKeys.delete(oldApiKey);
    }, 10 * 1000); 
};

let isFirstGeneration = true; 

app.post("/generate-api-key", apiKeyMiddleware, (req: Request, res: Response) => {
    const now = new Date();

    const secondsSinceLastGenerated = (now.getTime() - lastGenerated.getTime()) / 1000;

    if (!isFirstGeneration && secondsSinceLastGenerated < 10) {
        res.status(400).json({
            error: `API key was last generated ${Math.floor(secondsSinceLastGenerated)} seconds ago. Please wait ${
                10 - Math.floor(secondsSinceLastGenerated)
            } more seconds.`,
        });
        return;
    }

    const oldApiKey = API_KEY;
    API_KEY = generateApiKey();
    lastGenerated = now;
    isFirstGeneration = false; 

    handleExpiredKey(oldApiKey);

    res.json({
        message: "API key successfully regenerated.",
        newApiKey: API_KEY,
    });
});


app.post(
    "/citizen-info",
    apiKeyMiddleware,
    tcknMiddleware,
    (req: Request, res: Response): void => {
        const { tckn } = req.body;

        const user = citizenInfo.find((user) => user.tckn === tckn);

        if (!user) {
            res.status(404).json({ error: "User not found" });
            return;
        }

        res.json({
            name: user.name,
            birthDate: user.birthDate,
            address: user.address,
            phoneNumber: user.phoneNumber,
        });
    }
);

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
