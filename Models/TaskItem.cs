﻿namespace ToDoList.API.Models;

public class TaskItem
{
    public int Id { get; set; }
    public string Title { get; set; } = null!;
    public string? Description { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? DueDate { get; set; }
    public bool IsCompleted { get; set; } = false;
    public int UserId { get; set; }
    public User? User { get; set; }
}

