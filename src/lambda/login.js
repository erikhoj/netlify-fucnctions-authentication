import {createClient} from "../helpers/db-helper";
import bcrypt from "bcryptjs";
import {createJwtCookie} from "../helpers/jwt-helper";

export async function handler(event) {
    let errorStatusCode = 500;

    const dbClient = createClient();

    try {
        await dbClient.connect();
        const users = dbClient.usersCollection();

        const { email, password } = JSON.parse(event.body);
        const existingUser = await users.findOne({ email });

        if (!existingUser) {
            errorStatusCode = 401;
            throw new Error(`No user with email ${email} found`);
        }

        const matches = await bcrypt.compare(password, existingUser.password);
        if (!matches) {
            errorStatusCode = 401;
            throw new Error(`Invalid email or password provided`);
        }

        const userId = existingUser._id;

        return {
            statusCode: 200,
            headers: {
                'Set-Cookie': createJwtCookie(userId, email),
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ id: userId, email }),
        }
    } catch (err) {
        return {
            statusCode: errorStatusCode,
            body: JSON.stringify({ msg: err.message }),
        }
    } finally {
        dbClient.close();
    }
}