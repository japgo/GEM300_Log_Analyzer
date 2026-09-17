using Gem300.Core;
using Microsoft.Data.SqlClient;

namespace Gem300.Desktop;

public sealed class SqlReferenceLookup(string connectionString) : IReferenceLookup
{
    public async Task<ReferenceData> FetchAsync(IReadOnlyCollection<int> ceids,IReadOnlyCollection<int> rptids,CancellationToken token)
    {
        var events=new Dictionary<int,string>();var reports=new Dictionary<int,List<ReportVariable>>();
        await using var connection=new SqlConnection(connectionString);
        await connection.OpenAsync(token);
        foreach(var chunk in ceids.Chunk(500))
        {
            await using var command=connection.CreateCommand();command.CommandTimeout=5;
            string parameters=string.Join(',',chunk.Select((id,i)=>{command.Parameters.AddWithValue($"@p{i}",id);return $"@p{i}";}));
            command.CommandText=$"SELECT CEId, Name FROM [Events] WHERE CEId IN ({parameters})";
            await using var reader=await command.ExecuteReaderAsync(token);
            while(await reader.ReadAsync(token)) events[Convert.ToInt32(reader[0])]=reader.IsDBNull(1)?"":Convert.ToString(reader[1])!.Trim();
        }
        foreach(var chunk in rptids.Chunk(500))
        {
            await using var command=connection.CreateCommand();command.CommandTimeout=5;
            string parameters=string.Join(',',chunk.Select((id,i)=>{command.Parameters.AddWithValue($"@p{i}",id);return $"@p{i}";}));
            command.CommandText=$"SELECT rv.RepId,rv.Index_No,rv.VId,v.Name FROM ReportVariables rv LEFT JOIN Variables v ON v.VId=rv.VId WHERE rv.RepId IN ({parameters}) ORDER BY rv.RepId,rv.Index_No";
            await using var reader=await command.ExecuteReaderAsync(token);
            while(await reader.ReadAsync(token))
            {
                int rpt=Convert.ToInt32(reader[0]);
                if(!reports.TryGetValue(rpt,out var list)) reports[rpt]=list=[];
                list.Add(new(rpt,Convert.ToInt32(reader[1]),Convert.ToInt32(reader[2]),reader.IsDBNull(3)?"":Convert.ToString(reader[3])!.Trim()));
            }
        }
        return new(events,reports.ToDictionary(p=>p.Key,p=>p.Value.ToArray()));
    }
}
