import React, { useState, useEffect } from 'react';

function SignUp(props) {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [role, setRole] = useState('user');
    const [message, setMessage] = useState('');

    useEffect(() => {
        setEmail('');
        setPassword('');
        setMessage('');
    }, [props.resetKey]);

    const handleSignup = async (e) => {
        e.preventDefault();

        try{
        const response = await fetch('http://localhost:5000/signup', {
            method: 'POST',
            headers: {
            'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email, password, role }),
        });

        const data = await response.json();

        if (response.ok) {
            setMessage(`Sign up successful! Token: ${data.token}`);
        } else {
            setMessage(`Sign up failed: ${data.error}`); 
        }
        } catch (error) {
        setMessage(`Error: ${error.message}`);
        }
    };

    return (
        <div>
        <h2>Sign Up</h2>
        <form onSubmit={handleSignup}>
            <input
            type="email"
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            />
            <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            />
            <select value={role} onChange={(e) => setRole(e.target.value)}>
                <option value="user">User</option>
                <option value="admin">Admin</option>
            </select>

                <button type="submit">Sign Up</button>
            <p>{message}</p>
        </form>
        </div>
    );

}


export default SignUp;