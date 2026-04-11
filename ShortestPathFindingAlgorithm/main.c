#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>  // Added for printf

#define MAX_NODES 1024
#define INFINITY 1000000000
int n, dist[MAX_NODES][MAX_NODES];

void shortest_path(int s, int t, int path[])
{
    struct state
    {
        int predecessor;
        int length;
        enum{permanent, tentative} label;
    } state[MAX_NODES];

    int i, k, min;
    struct state *p;

    // Fix: The loop condition was incorrect
    for(p = &state[0]; p < &state[n]; p++)
    {
        p->predecessor = -1;
        p->length = INFINITY;
        p->label = tentative;
    } 

    state[t].length = 0;
    state[t].label = permanent;
    k = t;

    do
    {
        for(i = 0; i < n; i++)
        {
            if(dist[k][i] != 0 && state[i].label == tentative)
            {
                if(state[k].length + dist[k][i] < state[i].length)
                {
                    state[i].predecessor = k;
                    state[i].length = state[k].length + dist[k][i];
                }
            }
        }

        k = 0;
        min = INFINITY;

        for(i = 0; i < n; i++)
        {
            if(state[i].label == tentative && state[i].length < min)
            {
                min = state[i].length;
                k = i;
            }
        }

        state[k].label = permanent;
    } while (k != s); 

    i = 0;
    k = s;
    do
    {
        path[i++] = k;
        k = state[k].predecessor;
    } while (k >= 0);
    
    // Add terminator to path
    path[i] = -1;
}

// Added main function for testing
int main()
{
    // Example usage
    n = 5;
    
    // Initialize distance matrix (0 means no direct edge)
    for(int i = 0; i < n; i++)
        for(int j = 0; j < n; j++)
            dist[i][j] = 0;
    
    // Add some edges (undirected graph example)
    dist[0][1] = 4;
    dist[1][0] = 4;
    dist[0][2] = 2;
    dist[2][0] = 2;
    dist[1][2] = 1;
    dist[2][1] = 1;
    dist[1][3] = 5;
    dist[3][1] = 5;
    dist[2][3] = 8;
    dist[3][2] = 8;
    dist[3][4] = 3;
    dist[4][3] = 3;
    
    int path[MAX_NODES];
    int source = 0, target = 4;
    
    shortest_path(source, target, path);
    
    printf("Shortest path from %d to %d: ", source, target);
    for(int i = 0; path[i] != -1; i++)
    {
        printf("%d ", path[i]);
    }
    printf("\n");
    
    return 0;
}