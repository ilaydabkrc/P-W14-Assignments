using Microsoft.EntityFrameworkCore;
using Identity_and_Data_Protection.Models;

namespace Identity_and_Data_Protection.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<User> Users { get; set; }
    }
}
