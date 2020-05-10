using System;
using System.Threading.Tasks;
using DatingApp.API.Models;
using System.Security.Cryptography;
using System.Text.Unicode;
using System.Text;
using Microsoft.EntityFrameworkCore;

namespace DatingApp.API.Data
{
    public class AuthRepository : IAuthRepository
    {
        private readonly DataContext _context;
        public AuthRepository(DataContext context)
        {
            _context = context;
        }

        public async Task<User> Login(string username, string password)
        {
           var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
           if(user == null)
                return null;

            if(!VerifyPasswordHash(password, user.PasswordHash, user.PasswrordSalt))
                return null;
            
            return user;
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwrordSalt)
        {
           using(var hmac = new HMACSHA512(passwrordSalt))
           {
               var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
               for(int i = 0; i < computedHash.Length; i++)
               {
                   if(computedHash[i] != passwordHash[i])
                    return false;
               }
               return true;
           }
        }

        public async Task<User> Register(User user, string password)
        {
            byte[] passwordHash, passwordSalt;
            CreatePasswordHash(password, out passwordHash, out passwordSalt);
            user.PasswordHash = passwordHash;
            user.PasswrordSalt = passwordSalt;

            await _context.Users.AddAsync(user);
            await _context.SaveChangesAsync();

            return user;
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
           using( var hmac = new HMACSHA512())
           {
            passwordSalt = hmac.Key;
            passwordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
           }
        }

        public async Task<bool> UserExists(string username)
        {
           if(await _context.Users.AnyAsync(u => u.Username == username))
                return true;
           
           return false;
        }
    }
}